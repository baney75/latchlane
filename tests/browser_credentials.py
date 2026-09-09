"""Owner-only credential/import journey with disposable vaults and CSVs."""
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).parents[1]
ORIGIN = 'http://127.0.0.1:19476'
PASSWORD = 'disposable-credential-fixture'
GUARD = {'X-Latchlane': '1'}


def csv_bytes(headers, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out)
    writer.writerow(headers)
    writer.writerows(rows)
    return out.getvalue().encode()


def main():
    with tempfile.TemporaryDirectory(prefix='latchlane-credentials-browser-') as tmp:
        env = os.environ.copy()
        env['LATCHLANE_HOME'] = tmp
        python = str(ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python'))
        server = subprocess.Popen([python, '-c', 'from latchlane.cli import main; main()', 'start', '--port', '19476', '--no-open'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    if httpx.get(ORIGIN + '/api/status', trust_env=False).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(.1)
            else:
                raise AssertionError('Disposable credential host did not start')
            ticket = json.loads((Path(tmp) / 'owner-ticket.local.json').read_text())['url']
            with sync_playwright() as p:
                browser = p.chromium.launch()
                context = browser.new_context(viewport={'width': 1280, 'height': 1000})
                page = context.new_page()
                errors = []
                page.on('pageerror', lambda e: errors.append(str(e)))
                page.goto(ticket)
                page.locator('#password').fill(PASSWORD)
                page.locator('#confirm').fill(PASSWORD)
                page.locator('#enter').click()
                page.locator('#dashboard').wait_for(state='visible')

                def owner(method, path, body=None):
                    response = page.request.fetch(ORIGIN + path, method=method, headers=GUARD, data=body)
                    assert response.ok, (path, response.status)
                    return response.json()

                invite = owner('POST', '/api/invite')['code']
                token = httpx.post(ORIGIN + '/api/pair', headers=GUARD, json={'code': invite, 'name': 'Hermes fixture'}, trust_env=False).json()['token']
                agent = httpx.Client(base_url=ORIGIN, headers=GUARD | {'Authorization': 'Bearer ' + token}, trust_env=False)
                request = agent.post('/api/collections', json={'purpose': 'Configure the disposable test project', 'items': [{'name': 'team-api', 'origin': 'https://api.example.com', 'header': 'X-API-Key', 'prefix': ''}, {'name': 'team-login', 'kind': 'password', 'origin': 'https://example.com'}]})
                assert request.status_code == 200
                collection = request.json()
                assert 'value' not in collection
                page.goto(ORIGIN + collection['owner_path'])
                page.locator('#collection-dialog').wait_for(state='visible')
                assert 'Hermes fixture needs 2 credentials' in page.locator('#collection-title').inner_text()
                assert page.locator('#collection-secret-1').get_attribute('autocomplete').endswith('current-password')
                page.locator('#collection-secret-0').fill('fixture-api-never-real')
                page.locator('#collection-user-1').fill('fixture-user@example.com')
                page.locator('#collection-secret-1').fill('disposable-Unicode-🔐-päss')
                assert 'disposable-Unicode' not in page.locator('body').inner_text()
                page.screenshot(path=str(ROOT / 'docs/collection-form.png'), animations='disabled')
                for width in (320, 390, 1280):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.locator('#collection-save').click()
                page.locator('#collection-dialog').wait_for(state='hidden')
                expect(page.locator('#collection-fields input')).to_have_count(0)
                status = agent.get('/api/collections/' + collection['id']).json()
                assert status['status'] == 'completed'
                assert 'disposable-Unicode' not in json.dumps(status)
                assert 'fixture-user' not in json.dumps(status)
                assert agent.post('/api/requests', json={'key': 'team-login', 'purpose': 'Never send a login as an API header', 'path': '/'}).status_code == 422
                owner_keys = owner('GET', '/api/owner')['keys']
                assert all('value' not in k for k in owner_keys)
                assert next(k for k in owner_keys if k['name'] == 'team-login')['kind'] == 'password'

                # The ordinary form supports password-manager fields and edit without secret retrieval.
                page.locator('#add').click()
                page.locator('#key-kind').select_option('password')
                assert page.locator('#key-value').get_attribute('autocomplete').endswith('current-password')
                assert page.locator('#key-auth-options').is_hidden()
                page.locator('#key-name').fill('manual-login')
                page.locator('#key-origin').fill('https://manual.example.com')
                page.locator('#key-username').fill('fixture-owner')
                page.locator('#key-value').fill('manual-fixture-password')
                page.locator('#save-key').click()
                page.locator('#key-dialog').wait_for(state='hidden')
                page.get_by_role('button', name='Edit manual-login', exact=True).click()
                assert page.locator('#key-value').input_value() == ''
                page.locator('#key-username').fill('updated-fixture-owner')
                page.locator('#save-key').click()
                page.locator('#key-dialog').wait_for(state='hidden')

                def open_csv(headers, rows):
                    page.locator('#import-credentials').click()
                    page.locator('#import-file').set_input_files({'name': 'fixture-export.csv', 'mimeType': 'text/csv', 'buffer': csv_bytes(headers, rows)})
                    page.locator('#import-mapping').wait_for(state='visible')
                    page.locator('#import-review').click()
                    page.locator('#import-review-panel').wait_for(state='visible')

                # Each documented manager mapping, quoted commas/newlines, Unicode, and partial selection.
                formats = [
                    (['Title', 'Website', 'Username', 'Password', 'Notes'], [['1Password, fixture', 'https://one.example.com/login', 'one-user', 'one-fixture\npassword', 'not imported'], ['Do not import', 'https://skip.example.com', 'skip-user', 'unselected-fixture', '']]),
                    (['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'], [['', '0', 'login', 'Bitwarden fixture', '', '', '0', 'https://bit.example.com', 'bit-user', 'bit-fixture-ä', 'ignored']]),
                    (['Title', 'URL', 'Username', 'Password', 'Notes', 'OTPAuth'], [['Apple fixture', 'https://apple.example.com/signin', 'apple-user', 'apple-fixture-password', '', 'ignored']]),
                ]
                for headers, rows in formats:
                    open_csv(headers, rows)
                    assert page.locator('#import-save').is_disabled()
                    assert page.locator('#import-dialog').locator('input[type=password]').count() == 0
                    assert rows[0][headers.index('Password') if 'Password' in headers else headers.index('login_password')] not in page.locator('#import-dialog').inner_text()
                    page.locator('.import-selection input').first.check()
                    if headers[0] == 'Title' and headers[1] == 'Website':
                        page.set_viewport_size({'width': 390, 'height': 844})
                        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                        page.screenshot(path=str(ROOT / 'docs/import-review.png'), animations='disabled')
                    page.locator('#import-save').click()
                    page.locator('#import-dialog').wait_for(state='hidden')
                    assert page.locator('#import-file').input_value() == ''
                    expect(page.locator('#import-entries')).to_be_empty()
                    page.set_viewport_size({'width': 1280, 'height': 1000})
                names = [k['name'] for k in agent.get('/api/keys').json()['keys']]
                assert 'do-not-import' not in names
                assert {'1password-fixture', 'bitwarden-fixture', 'apple-fixture'} <= set(names)

                # Generic mapping and cancellation never submit a credential.
                page.locator('#import-credentials').click()
                page.locator('#import-file').set_input_files({'name': 'generic.csv', 'mimeType': 'text/csv', 'buffer': csv_bytes(['Label', 'Address', 'Account ID', 'Hidden'], [['Generic fixture', 'https://generic.example.com', 'generic-user', 'generic-secret-never-saved']])})
                page.locator('#import-mapping').wait_for(state='visible')
                for key, column in {'name': '0', 'origin': '1', 'username': '2', 'value': '3'}.items():
                    page.locator('#map-' + key).select_option(column)
                page.locator('#import-review').click()
                page.locator('.import-selection input').first.check()
                page.locator('[data-close="import-dialog"]').click()
                expect(page.locator('#import-entries')).to_be_empty()
                assert len(agent.get('/api/keys').json()['keys']) == len(names)

                # A pending file read cannot repopulate a dismissed dialog.
                page.locator('#import-credentials').click()
                page.evaluate('''() => { window.__originalFileText = File.prototype.text; File.prototype.text = function() { return new Promise(resolve => window.__resolveFile = resolve); }; }''')
                page.locator('#import-file').set_input_files({'name': 'late.csv', 'mimeType': 'text/csv', 'buffer': b'fixture'})
                page.locator('[data-close="import-dialog"]').click()
                page.evaluate('''() => { window.__resolveFile('Title,URL,Password\\nlate,https://late.example.com,late-secret'); File.prototype.text = window.__originalFileText; }''')
                page.wait_for_timeout(50)
                assert page.locator('#import-file').input_value() == ''
                assert page.locator('#import-map-fields').inner_text() == ''

                # Malformed CSV reports a format error, never echoes its content.
                page.locator('#import-credentials').click()
                page.locator('#import-file').set_input_files({'name': 'broken.csv', 'mimeType': 'text/csv', 'buffer': b'Title,URL,Password\n"unterminated,https://broken.example.com,not-a-real-secret'})
                page.locator('#import-dialog .dialog-notice.error').wait_for(state='visible')
                assert 'not-a-real-secret' not in page.locator('#import-dialog').inner_text()
                page.locator('[data-close="import-dialog"]').click()

                # Owner can still explicitly enable YOLO; password HTTP remains prohibited.
                page.locator('[data-mode="yolo"]').click()
                page.locator('#confirm-mode').click()
                page.locator('#mode-dialog').wait_for(state='hidden')
                assert owner('GET', '/api/owner')['mode'] == 'yolo'
                assert agent.post('/api/requests', json={'key': 'team-login', 'path': '/', 'purpose': 'Wrong transport fixture'}).status_code == 422
                lease = agent.post('/api/requests', json={'key': 'team-login', 'kind': 'lease', 'purpose': 'Approved fixture child process'}).json()
                assert lease['status'] == 'approved'
                result = agent.post('/api/requests/' + lease['id'] + '/consume').json()
                assert result['value'] == 'disposable-Unicode-🔐-päss'
                result.clear()

                # A delayed decline response must not dismiss a newer collection form.
                for outcome in ('success', 'error'):
                    first = agent.post('/api/collections', json={'purpose': 'First delayed ' + outcome, 'items': [{'name': 'late-first-' + outcome, 'kind': 'password', 'origin': 'https://first.example.com'}]}).json()
                    second = agent.post('/api/collections', json={'purpose': 'Second delayed ' + outcome, 'items': [{'name': 'late-second-' + outcome, 'kind': 'password', 'origin': 'https://second.example.com'}]}).json()
                    first_card = page.locator('#collections-list article').filter(has_text='First delayed ' + outcome)
                    first_card.get_by_role('button', name='Fill privately').click()
                    held = []
                    pattern = '**/api/owner/collections/' + first['id'] + '/cancel'
                    page.route(pattern, lambda route: held.append(route))
                    page.locator('#collection-cancel').click()
                    page.wait_for_timeout(50)
                    assert len(held) == 1
                    page.locator('[data-close="collection-dialog"]').click()
                    expect(page.locator('#collection-fields input')).to_have_count(0)
                    second_card = page.locator('#collections-list article').filter(has_text='Second delayed ' + outcome)
                    second_card.get_by_role('button', name='Fill privately').click()
                    page.locator('#collection-secret-0').fill('new-form-private-fixture')
                    if outcome == 'success':
                        held[0].fulfill(response=held[0].fetch())
                    else:
                        held[0].fulfill(status=500, content_type='application/json', body='{"detail":"Fixture failure"}')
                    page.wait_for_timeout(100)
                    expect(page.locator('#collection-dialog')).to_be_visible()
                    expect(page.locator('#collection-secret-0')).to_have_value('new-form-private-fixture')
                    expect(page.locator('#collection-cancel')).to_be_enabled()
                    page.unroute(pattern)
                    page.locator('[data-close="collection-dialog"]').click()
                    expect(page.locator('#collection-fields input')).to_have_count(0)
                    owner('POST', '/api/owner/collections/' + second['id'] + '/cancel')
                    if outcome == 'error':
                        owner('POST', '/api/owner/collections/' + first['id'] + '/cancel')

                # Locking from another owner surface clears unsaved import and collection fields.
                pending = agent.post('/api/collections', json={'purpose': 'Cancelled fixture', 'items': [{'name': 'cancelled-login', 'kind': 'password', 'origin': 'https://cancel.example.com'}]}).json()
                page.goto(ORIGIN + pending['owner_path'])
                page.locator('#collection-dialog').wait_for(state='visible')
                page.locator('#collection-secret-0').fill('unsaved-fixture-password')
                owner('POST', '/api/lock')
                page.locator('#welcome').wait_for(state='visible', timeout=8000)
                expect(page.locator('#collection-fields input')).to_have_count(0)
                assert page.locator('#collection-dialog').is_hidden()
                assert not errors, errors
                browser.close()
                print('PASS: private batch collection, password types, 1Password/Bitwarden/Apple and generic CSV imports, partial selection, cancellation, late-file guard, malformed input, lock scrub, YOLO boundaries, and responsive owner forms. Disposable data only.')
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == '__main__':
    main()
