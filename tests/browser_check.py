"""Disposable real-browser flow. Never uses a user's vault or clipboard."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import httpx
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).parents[1]

def main():
    with tempfile.TemporaryDirectory(prefix='latchlane-browser-') as tmp:
        env=os.environ.copy();env['LATCHLANE_HOME']=tmp
        python=str(ROOT/'.venv'/('Scripts/python.exe' if os.name=='nt' else 'bin/python'))
        from latchlane.vault import Vault
        v=Vault(Path(tmp));v.initialize('browser-fixture-passphrase')
        process=subprocess.Popen([python,'-c','from latchlane.cli import main; main()','start','--port','19473','--no-open'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    if httpx.get('http://127.0.0.1:19473/api/status',trust_env=False).status_code==200:break
                except httpx.HTTPError: pass
                time.sleep(.1)
            with sync_playwright() as p:
                browser=p.chromium.launch()
                context=browser.new_context(viewport={'width':1440,'height':1050})
                page=context.new_page();errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto('http://127.0.0.1:19473')
                page.locator('#password').fill('browser-fixture-passphrase');page.locator('#enter').click();page.locator('#dashboard').wait_for(state='visible')
                assert page.locator('[data-mode="ask"]').get_attribute('aria-pressed')=='true'
                page.locator('#add').click()
                page.locator('#key-name').fill('invalid-origin')
                page.locator('#key-origin').fill('http://api.example.com')
                page.locator('#key-value').fill('disposable-invalid-fixture')
                page.locator('#key-form [type=submit]').click()
                alert=page.locator('#key-dialog .dialog-notice.error')
                alert.wait_for(state='visible')
                assert alert.get_attribute('role')=='alert'
                assert alert.evaluate('(el) => { const r=el.getBoundingClientRect(); return el.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)); }')
                page.locator('#key-name').fill('studio-ai');page.locator('#key-origin').fill('https://api.example.com');page.locator('#key-value').fill('dummy-browser-key-not-real');page.locator('#key-form summary').click();page.locator('#safe-paths').fill('/v1/models');page.locator('#key-form [type=submit]').click();page.locator('#key-dialog').wait_for(state='hidden')
                page.locator('#keys strong').get_by_text('studio-ai',exact=True).wait_for()
                assert 'dummy-browser-key-not-real' not in page.locator('body').inner_text()
                page.locator('[data-mode="auto"]').click();page.locator('#confirm-mode').click();page.locator('[data-mode="auto"][aria-pressed="true"]').wait_for()
                page.locator('#notice').wait_for(state='hidden',timeout=10000);page.screenshot(path=str(ROOT/'docs/console.png'),full_page=True,animations='disabled')
                page.locator('#sync-guide').click();assert page.locator('#sync-dialog').is_visible();page.locator('#sync-dialog [data-close]').first.click()
                for width in (320,390,768,1280):
                    page.set_viewport_size({'width':width,'height':1000});page.wait_for_timeout(100)
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),f'overflow at {width}'
                    if width==390:page.screenshot(path=str(ROOT/'docs/mobile.png'),full_page=True,animations='disabled')
                page.locator('#pair').click();page.locator('#pair-result').wait_for(state='visible');code=page.locator('#pair-code').inner_text();assert len(code)>20
                # Pair via actual HTTP, then exercise an approval in the visible UI.
                with httpx.Client(base_url='http://127.0.0.1:19473',headers={'X-Latchlane':'1'},trust_env=False) as agent:
                    token=agent.post('/api/pair',json={'code':code,'name':'Design agent'}).json()['token']
                    agent.headers['Authorization']='Bearer '+token
                    rid=agent.post('/api/requests',json={'key':'studio-ai','kind':'lease','purpose':'Run the local design preview'}).json()['id']
                    page.get_by_text('Approve once',exact=True).click(timeout=10000)
                    assert agent.post('/api/requests/'+rid+'/consume').json()['value']=='dummy-browser-key-not-real'
                page.locator('#lock').click();page.locator('#welcome').wait_for(state='visible')
                assert not errors,errors
                browser.close()
                print('PASS: real browser add/mode/pair/approval/lock; 320/390/768/1280px without overflow. No user clipboard accessed.')
        finally:
            process.terminate();process.wait(timeout=10)

if __name__=='__main__':main()
