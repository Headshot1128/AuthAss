"""Transfer an in-memory SQLite snapshot to the private Site, never to Git.

Configuration (including the short-lived migration credential) is supplied only
through stdin. The hosted runtime re-encrypts license display values. Existing
sessions are deliberately not copied.
"""
import json
import sys
from pathlib import Path
import httpx

from backend.config import Settings
from backend.db import connect
from backend.license_keys import cipher


def main():
    print('Ready for private migration configuration on stdin.',flush=True)
    config=json.loads(sys.stdin.readline())
    headers={}
    if config.get('bypass'):
        headers['OAI-Sites-Authorization']='Bearer '+config['bypass']
    with httpx.Client(base_url=config['url'],headers=headers,timeout=120,follow_redirects=False,trust_env=False) as client:
        if config['action']=='probe':
            for index in range(3):
                result=client.post('/v1/admin/login',json={'username':'hosted-check-not-a-user','password':'known runtime test password'})
                print('Hosted password check',index+1,':',result.status_code,flush=True)
                if result.status_code!=401:
                    raise SystemExit('Hosted password checks failed; migration was not attempted.')
            return
        if config['action']!='import':
            raise SystemExit('Unknown migration action')
        settings=Settings.environment()
        with connect(settings) as db:
            snapshot={table:[dict(row) for row in db.execute('SELECT * FROM '+table)]
                      for table in ['users','licenses','permissions','variables','files','audit_logs']}
            if snapshot['files']:
                raise SystemExit('Private files require a separate R2 transfer before this import.')
            for license in snapshot['licenses']:
                encoded=license.pop('key_ciphertext',None)
                license['display_key']=cipher(settings).decrypt(encoded.encode()).decode() if encoded else None
            # No passwords, database contents, or display keys are printed or written to export files.
            result=client.post('/_migration/import',json=snapshot,headers={'X-Migration-Token':config['token']})
            print('Import HTTP status:',result.status_code,flush=True)
            if result.status_code!=200:
                try:print('Import error code:',result.json().get('error'),flush=True)
                except ValueError:pass
                raise SystemExit(1)
            print('Imported record counts:',json.dumps({table:len(rows) for table,rows in snapshot.items()}),flush=True)


if __name__=='__main__':main()
