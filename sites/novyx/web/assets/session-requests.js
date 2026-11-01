// Reads may run independently; writes stay ordered and token rotation is shared.
export function createSessionRequests({session, refresh, send, fatal, changed, now = Date.now}) {
  let writes = Promise.resolve(), refreshing = null;
  const cancelled = () => new DOMException('Request cancelled','AbortError');
  const unauthorized = () => Object.assign(new Error('Sign in to continue.'),{code:'authentication_required',status:401});
  function check(epoch, signal) {
    if (signal?.aborted) throw cancelled();
    const current = session();
    if (current.epoch !== epoch || !current.access) throw unauthorized();
    return current;
  }
  function rotate(epoch) {
    if (refreshing?.epoch === epoch) return refreshing.promise;
    const flight = {epoch,promise:null};
    flight.promise = Promise.resolve().then(() => refresh(epoch)).finally(() => {
      if (refreshing === flight) refreshing = null;
    });
    refreshing = flight;
    return flight.promise;
  }
  return {
    reset() { writes = Promise.resolve(); refreshing = null; },
    request(path, method = 'GET', body, binary = false, {signal} = {}) {
      const epoch = session().epoch;
      const execute = async () => {
        try {
          let current = check(epoch,signal);
          if (current.expiry*1000 <= now()+15000) await rotate(epoch);
          current = check(epoch,signal);
          const token = current.access;
          let result;
          try { result = await send(path,method,body,token,binary,signal); }
          catch (error) {
            current = check(epoch,signal);
            const rotating = refreshing?.epoch === epoch;
            const stale = token !== current.access;
            if (error.code !== 'expired' && !(error.code === 'invalid_token' && (rotating || stale))) throw error;
            if (rotating) await refreshing.promise;
            else if (!stale) await rotate(epoch);
            current = check(epoch,signal);
            result = await send(path,method,body,current.access,binary,signal);
          }
          check(epoch,signal);
          if (method !== 'GET') changed();
          return result;
        } catch (error) {
          const deliveryFailure=['email_delivery_failed','email_not_configured'].includes(error.code)&&error.status===503;
          if (!deliveryFailure && error.name !== 'AbortError' && epoch === session().epoch &&
              (error.status === 401 || error.status >= 500 || !error.status || error.code === 'invalid_response')) fatal(error);
          throw error;
        }
      };
      if (method === 'GET') return execute();
      const task = writes.then(execute);
      writes = task.catch(() => {});
      return task;
    },
  };
}
