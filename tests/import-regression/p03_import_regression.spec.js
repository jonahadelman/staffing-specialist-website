/* P0.3 PERMANENT REGRESSION — resume/CSV importer field mapping.
   Fixtures are byte-exact prefixes of four production resumes/filenames that reproduced the
   2026-07-24 importer defects: Glen Gerber (imported as "SOUTHWEST AIRLINES"), Eric Allen
   (imported as "Ursa Technologies"), Todd Kozey (own initial+surname in location; Format-C
   experience layout), Todd Goulston ("_rev C" filename suffix imported as surname).
   Run: node p03_import_regression.spec.js — requires Playwright + Chromium and the repo builds.
   16 checks x 2 platforms must ALL PASS before any release touching
   grabName / grabTitle / grabCompany / grabLocation / tbNameLooksValid / tbCurrentRole. */
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const GLEN = JSON.parse(fs.readFileSync(path.join(__dirname, 'glen.txt.json'), 'utf8'));
const ERIC = JSON.parse(fs.readFileSync(path.join(__dirname, 'eric.txt.json'), 'utf8'));
const KOZEY = JSON.parse(fs.readFileSync(path.join(__dirname, 'kozey.txt.json'), 'utf8'));
const REPO = path.resolve(__dirname, '..', '..');

(async () => {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium', args: ['--no-sandbox'] });
  let allPass = true;
  for (const site of ['elbit', 'hiarc']) {
    const page = await browser.newPage();
    const errs = [];
    page.on('pageerror', e => errs.push(String(e).slice(0, 150)));
    await page.route('https://cdn.jsdelivr.net/**', r => r.fulfill({ path: '/tmp/package/dist/umd/supabase.js', contentType: 'application/javascript' }));
    await page.route('https://cdnjs.cloudflare.com/**', r => r.fulfill({ body: '/*stub*/', contentType: 'application/javascript' }));
    await page.route('https://apxirlgoiruvczhwdgue.supabase.co/**', r => r.fulfill({ body: '[]', contentType: 'application/json' }));
    await page.goto('file://' + path.join(REPO, site + '.html'), { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(400);
    const res = await page.evaluate(({ GLEN, ERIC, KOZEY }) => {
      const rep = (t, f) => ({ name: grabName(t, f), title: grabTitle(t), company: grabCompany(t), loc: grabLocation(t) });
      return {
        glen: rep(GLEN, 'gerber glen. 07.21.26.pdf'),
        eric: rep(ERIC, 'Eric.L.Allen.Resume.pdf'),
        kozey: rep(KOZEY, 'Todd Kozey_Resume (Executive).pdf'),
        goulstonName: grabName('', 'Todd Goulston Resume_rev C.doc'),
        guardCorp: fullName({ firstName: 'Southwest', lastName: 'Airlines' }),
        guardCorp2: fullName({ firstName: 'Ursa', lastName: 'Technologies' }),
        guardReal: fullName({ firstName: 'Glen', lastName: 'Gerber' })
      };
    }, { GLEN, ERIC, KOZEY });
    const checks = {
      'Glen name = GLEN GERBER (not an employer)': res.glen.name.first.toUpperCase() === 'GLEN' && res.glen.name.last.toUpperCase() === 'GERBER',
      'Glen company = Southwest Airlines': res.glen.company === 'Southwest Airlines',
      'Glen title = Operations Portfolio Manager': res.glen.title === 'Operations Portfolio Manager',
      'Glen location clean (no PMP)': /^Northlake, Tex/.test(res.glen.loc),
      'Eric name = Eric Allen (not Ursa Technologies)': res.eric.name.first === 'Eric' && res.eric.name.last === 'Allen',
      'Eric company = Lockheed Martin (not "Current Firefly...")': res.eric.company === 'Lockheed Martin',
      'Eric title = current role': res.eric.title === 'Multi-Functional Manufacturing Supervisor',
      'Eric location clean (no Supervisor)': /^Lake Worth, TX/.test(res.eric.loc),
      'Kozey name = Todd Kozey': /todd/i.test(res.kozey.name.first) && /kozey/i.test(res.kozey.name.last),
      'Kozey location clean (no M. KOZEY)': /^Summerville, SC/i.test(res.kozey.loc),
      'Kozey company = Acquisition Logistics': res.kozey.company === 'Acquisition Logistics',
      'Kozey title = current role': res.kozey.title === 'Senior Technical Analyst Team Lead',
      'Goulston: rev-suffix never a surname': res.goulstonName.first === 'Todd' && /goulston/i.test(res.goulstonName.last || ''),
      'Display guard: corporate names never render as people': res.guardCorp === 'Name Requires Review' && res.guardCorp2 === 'Name Requires Review',
      'Display guard: real names untouched': res.guardReal === 'Glen Gerber',
      'Zero page errors': errs.length === 0
    };
    const failed = Object.keys(checks).filter(k => !checks[k]);
    if (failed.length) allPass = false;
    console.log('=== ' + site.toUpperCase() + ' P0.3: ' + (failed.length ? 'FAIL' : 'ALL PASS (16 checks)') + ' ===');
    failed.forEach(k => console.log('  FAIL:', k));
    if (failed.length) console.log('  actual:', JSON.stringify(res));
    await page.close();
  }
  console.log('P0.3 REGRESSION:', allPass ? 'ALL PASS' : 'FAIL');
  await browser.close();
  process.exit(allPass ? 0 : 1);
})();
