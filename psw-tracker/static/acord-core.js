/* ACORD filler core: quote sheet -> ACORD 125 / 126 / 130 field values.
   Works in the browser (globals XLSX, PDFLib) and in Node (require). */
(function (root) {
  'use strict';

  // ---------- defaults Alex can change in the app (saved in the browser) ----------
  const DEFAULT_SETTINGS = {
    agency_name: 'PACIFIC SOUTHWEST INSURANCE SERVICES',
    agency_street: '9036 Reseda Blvd Ste 105',
    agency_city_state_zip: 'Northridge, CA 91324',
    producer_name: 'Alex Koutsoubas',
    producer_phone: '818-701-1033',
    producer_fax: '866-581-8854',
    producer_email: 'info@pswinsurance.com',
    producer_license: '',
    national_producer_number: '',
    gl_general_aggregate: '2,000,000',
    gl_products_aggregate: '1,000,000',
    gl_personal_adv: '1,000,000',
    gl_each_occurrence: '1,000,000',
    gl_damage_rented: '100,000',
    gl_medical_expense: '5,000',
    wc_each_accident: '1,000,000',
    wc_policy_limit: '1,000,000',
    wc_each_employee: '1,000,000',
    // keyword -> WC class code, used only when the quote sheet has no class code
    wc_class_lookup: 'residential clean|home clean|house clean|maid|janitorial residential = 9096',
  };

  // ---------- quote sheet labels ----------
  const LABELS = [
    ['lead_date', /^leaddate/], ['lead_source', /^leadsource/],
    ['client_name', /^clientname/], ['dba', /^dba$/], ['entity_type', /^ind.*(corp|copr)|^entity/],
    ['contact_name', /^contactname/], ['phone', /^phone/], ['email', /^email/],
    ['mailing_address', /^mailingaddress/], ['property_address', /^propertyaddress/],
    ['description', /^descriptionofbusiness/], ['detailed_description', /^detaileddescription/],
    ['line_of_business', /^lineofbusiness/], ['eff_date', /^effdate/], ['exp_date', /^expdate/],
    ['currently_insured', /^currentlyinsured/], ['current_carrier_price', /^currentcomp/],
    ['year_started', /^yearbiz|^yearbusiness/], ['years_experience', /^yearsexp/],
    ['gross_receipts', /^grossrec|^grosssales/], ['payroll', /^payroll/], ['subout', /^subs?out|^subcontract(ed|or)?(cost|pay|paid)/],
    ['full_time', /fulltime/], ['part_time', /parttime/], ['claims', /^anyclaims|^claims/],
    ['bldg_address', /^ad+ress$/], ['bldg_year_built', /^yrbuilt|^yearbuilt/], ['bldg_sqft', /^sqft/],
    ['bldg_construction', /^constructiontype/], ['bldg_roof', /^rooftype/],
    ['tax_id', /^taxid|^fein/],
    ['owner1', /^owner1/], ['owner2', /^owner2/], ['owner3', /^owner3/], ['owner4', /^owner4/],
    ['class_code1', /^classco\w*1$/], ['class_code2', /^classco\w*2$/], ['class_code3', /^classco\w*3$/], ['class_code4', /^classco\w*4$/],
    ['ai1', /^ai1$/], ['ai2', /^ai2$/], ['ai3', /^ai3$/], ['ai4', /^ai4$/],
  ];
  const BLDG = ['bldg_address', 'bldg_year_built', 'bldg_sqft', 'bldg_construction', 'bldg_roof'];

  // Order + friendly names for the review screen
  const DATA_FIELDS = [
    ['client_name', 'Client name'], ['dba', 'DBA'], ['entity_type', 'Ind/Corp/Part/LLC'],
    ['contact_name', 'Contact name'], ['phone', 'Phone'], ['email', 'Email'],
    ['mailing_address', 'Mailing address'], ['property_address', 'Property address'], ['interest', 'Interest (owner / tenant)'],
    ['description', 'Description of business'], ['detailed_description', 'Detailed description'],
    ['line_of_business', 'Line of business'], ['eff_date', 'Effective date'], ['exp_date', 'Expiration date'],
    ['currently_insured', 'Currently insured?'], ['current_carrier_price', 'Current carrier / price'],
    ['year_started', 'Year business started'], ['years_experience', 'Years experience'],
    ['gross_receipts', 'Gross receipts'], ['gl_gross_receipts', 'Gross receipts (126)'], ['payroll', 'Payroll'], ['subout', 'Subout ($ paid to subs)'],
    ['full_time', '# Full time employees'], ['part_time', '# Part time employees'], ['claims', 'Any claims'],
    ['bldg1_address', 'Building 1 address'], ['bldg1_year_built', 'Building 1 year built'], ['bldg1_sqft', 'Building 1 sq ft'],
    ['bldg1_construction', 'Building 1 construction'], ['bldg1_roof', 'Building 1 roof'],
    ['bldg2_address', 'Building 2 address'], ['bldg2_sqft', 'Building 2 sq ft'],
    ['bldg3_address', 'Building 3 address'], ['bldg3_sqft', 'Building 3 sq ft'],
    ['tax_id', 'Tax ID / FEIN'],
    ['owner1', 'Owner 1 (name / DOB / %)'], ['owner2', 'Owner 2'], ['owner3', 'Owner 3'], ['owner4', 'Owner 4'],
    ['class_code1', 'WC class code 1'], ['class_code2', 'WC class code 2'], ['class_code3', 'WC class code 3'], ['class_code4', 'WC class code 4'],
    ['ai1', 'Additional insured 1'], ['ai2', 'Additional insured 2'], ['ai3', 'Additional insured 3'], ['ai4', 'Additional insured 4'],
    ['p_bldg_desc', 'Building description'], ['p_subj1', 'Coverage 1'], ['p_amt1', 'Coverage 1 amount'], ['p_subj2', 'Coverage 2'], ['p_amt2', 'Coverage 2 amount'], ['p_subj3', 'Coverage 3'], ['p_amt3', 'Coverage 3 amount'], ['p_hydrant', 'Distance to hydrant (ft)'], ['p_station', 'Distance to fire station (mi)'], ['p_stories', '# Stories'], ['p_basements', '# Basements'], ['p_wiring_yr', 'Wiring updated (year)'], ['p_roof_yr', 'Roofing updated (year)'], ['p_plumbing_yr', 'Plumbing updated (year)'], ['p_heating_yr', 'Heating updated (year)'], ['p_exp_right', 'Right exposure'], ['p_exp_left', 'Left exposure'], ['p_exp_front', 'Front exposure'], ['p_exp_rear', 'Rear exposure'], ['p_burglar', 'Burglar alarm type'], ['p_fire_prot', 'Premises fire protection'], 
    ['lead_date', 'Lead date'], ['lead_source', 'Lead source'],
  ];

  const norm = s => String(s == null ? '' : s).toLowerCase().replace(/[^a-z0-9]/g, '');
  const clean = s => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  const pad = n => String(n).padStart(2, '0');
  const fmtDate = d => `${pad(d.getMonth() + 1)}/${pad(d.getDate())}/${d.getFullYear()}`;
  function excelSerialToDate(n) { const d = new Date(Math.round((n - 25569) * 86400000)); return new Date(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()); }

  function cellToString(v) {
    if (v == null) return '';
    if (v instanceof Date) return fmtDate(v);
    if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(Math.round(v * 100) / 100);
    return clean(v);
  }

  // ---------- read the quote sheet ----------
  function parseQuoteSheet(workbook, XLSXlib) {
    const X = XLSXlib || root.XLSX;
    const data = {};
    DATA_FIELDS.forEach(([k]) => data[k] = '');
    for (const name of workbook.SheetNames) {
      const rows = X.utils.sheet_to_json(workbook.Sheets[name], { header: 1, raw: true, defval: null });
      for (const row of rows) {
        if (!row) continue;
        for (let c = 0; c < Math.min(row.length, 3); c++) {
          const label = row[c];
          if (typeof label !== 'string' || !label.trim()) continue;
          const n = norm(label);
          const hit = LABELS.find(([, re]) => re.test(n));
          if (!hit) continue;
          const key = hit[0];
          const vals = row.slice(c + 1);
          if (BLDG.includes(key)) {
            for (let b = 0; b < 3; b++) {
              const k = key.replace('bldg_', `bldg${b + 1}_`);
              if (vals[b] != null && cellToString(vals[b]) !== '') data[k] = cellToString(vals[b]);
            }
          } else {
            let v = vals.find(x => x != null && cellToString(x) !== '');
            if (v == null) v = '';
            if ((key === 'lead_date' || key === 'eff_date' || key === 'exp_date') && typeof v === 'number' && v > 20000) v = fmtDate(excelSerialToDate(v));
            if (!data[key]) data[key] = cellToString(v);
          }
          break;
        }
      }
      if (data.client_name) break;
    }
    return finishQuoteData(data);
  }

  // Quote sheet saved as a fillable PDF by the Quote Sheet tool: field names are f_<key> and b<n>_<part>
  function parseQuotePdfFields(fields) {
    const data = {};
    DATA_FIELDS.forEach(([k]) => data[k] = '');
    const BPART = { address: 'address', yr: 'year_built', sqft: 'sqft', const: 'construction', roof: 'roof' };
    for (const [name, raw] of Object.entries(fields)) {
      const v = clean(raw); if (!v) continue;
      let m;
      if ((m = name.match(/^f_(\w+)$/)) && m[1] in data) data[m[1]] = v;
      else if ((m = name.match(/^b([123])_(\w+)$/)) && BPART[m[2]]) data[`bldg${m[1]}_${BPART[m[2]]}`] = v;
    }
    return finishQuoteData(data);
  }

  function finishQuoteData(data) {
    data.gl_gross_receipts = data.gross_receipts;
    data.interest = 'Owner';
    if (!data.subout && /nosub/.test(norm(data.payroll))) data.subout = '$0';
    Object.assign(data, { p_bldg_desc: 'main building', p_subj1: 'Dwelling', p_amt1: '', p_subj2: 'BPP', p_amt2: '', p_subj3: 'BI/EE', p_amt3: '', p_hydrant: '', p_station: '', p_stories: '', p_basements: '', p_wiring_yr: '', p_roof_yr: '', p_plumbing_yr: '', p_heating_yr: '', p_exp_right: '', p_exp_left: '', p_exp_front: '', p_exp_rear: '', p_burglar: 'NA', p_fire_prot: 'NA' });
    return data;
  }

  // ---------- helpers ----------
  const STATES = 'AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY'.split(' ');
  const CITY_ABBR = { SJ: 'San Jose', SF: 'San Francisco', LA: 'Los Angeles', SD: 'San Diego', SM: 'Santa Monica', LB: 'Long Beach', NOHO: 'North Hollywood', SAC: 'Sacramento', OAK: 'Oakland', SB: 'Santa Barbara', SC: 'Santa Clara', RC: 'Rancho Cucamonga', SFV: 'San Fernando Valley' };
  const SUFFIX = /^(st|street|ave|avenue|av|blvd|boulevard|rd|road|dr|drive|ln|lane|way|ct|court|pl|place|cir|circle|pkwy|parkway|hwy|highway|ter|terrace|trl|trail|sq|loop|row|walk|path|plz|plaza)\.?$/i;
  const UNIT = /^(#\S*|apt\.?|unit|ste\.?|suite|bldg|fl|floor|spc|space|rm|room)$/i;

  function parseAddress(raw) {
    const out = { street: '', city: '', state: '', zip: '', raw: clean(raw) };
    let s = clean(raw);
    if (!s) return out;
    const zm = s.match(/\b(\d{5})(?:-(\d{4}))?\s*$/);
    if (zm) { out.zip = zm[0].trim(); s = s.slice(0, zm.index).trim().replace(/,$/, ''); }
    const sm = s.match(/(?:,\s*|\s)([A-Za-z]{2})\.?$/);
    if (sm && STATES.includes(sm[1].toUpperCase())) { out.state = sm[1].toUpperCase(); s = s.slice(0, sm.index).trim().replace(/,$/, ''); }
    let street = s, city = '';
    if (s.includes(',')) {
      const parts = s.split(',').map(x => x.trim()).filter(Boolean);
      city = parts.length > 1 ? parts.pop() : '';
      street = parts.join(', ');
    } else {
      const t = s.split(' ');
      let idx = -1;
      for (let i = 1; i < t.length; i++) if (SUFFIX.test(t[i])) idx = i;
      if (idx >= 0) {
        let j = idx + 1;
        if (j < t.length && /^[NSEW]$/i.test(t[j])) j++;
        if (j < t.length && UNIT.test(t[j])) j += (t[j].startsWith('#') && t[j].length > 1) ? 1 : 2;
        else if (j < t.length && /^\d+[A-Za-z]?$/.test(t[j]) && j < t.length - 1) j++;
        street = t.slice(0, j).join(' ');
        city = t.slice(j).join(' ');
      }
    }
    const abbr = CITY_ABBR[city.toUpperCase().replace(/[^A-Z]/g, '')];
    if (abbr) city = abbr;
    out.street = clean(street);
    out.city = city.replace(/\b\w/g, c => c.toUpperCase()).replace(/\B\w/g, c => c.toLowerCase()) || '';
    if (!out.state && out.zip && /^9[0-6]/.test(out.zip)) out.state = 'CA';
    return out;
  }
  const cityLine = a => [a.city, [a.state, a.zip].filter(Boolean).join(' ')].filter(Boolean).join(', ');
  const fullAddr = a => [a.street, cityLine(a)].filter(Boolean).join(', ');

  function parseMoney(s) {
    const m = String(s || '').replace(/,/g, '').match(/\$?\s*(\d+(?:\.\d+)?)\s*(k|m|mil|million|thousand)?\b/i);
    if (!m) return null;
    let n = parseFloat(m[1]);
    const u = (m[2] || '').toLowerCase();
    if (u === 'k' || u === 'thousand') n *= 1000; else if (u) n *= 1000000;
    return Math.round(n);
  }
  const money = n => n == null ? '' : n.toLocaleString('en-US');
  function moneyRest(s) { // "20k  no subs" -> {amount:"20k", rest:"no subs"}
    const t = clean(s); const m = t.match(/^\$?\s*[\d,.]+\s*(k|m|mil)?\b/i);
    return m ? { amount: m[0].trim(), rest: t.slice(m[0].length).replace(/^[\s,;-]+/, '') } : { amount: '', rest: t };
  }
  function fixEmail(e) {
    return clean(e).replace(/\s/g, '').replace(/@gmial\./i, '@gmail.').replace(/@gmai\.com/i, '@gmail.com').replace(/@gamil\./i, '@gmail.')
      .replace(/@gmail\.con$/i, '@gmail.com').replace(/@yahooo\./i, '@yahoo.').replace(/@hotmial\./i, '@hotmail.');
  }
  const yes = s => /^(y|yes|true|1)/i.test(clean(s));
  const isNone = s => !clean(s) || /^(no|none|n|0|n\/a|na|nope|no claims|no losses)\.?$/i.test(clean(s));
  const cap = s => { s = clean(s); return s ? s[0].toUpperCase() + s.slice(1) : s; };

  function parseDateLoose(s, today) {
    s = clean(s);
    if (!s) return null;
    let m = s.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](\d{2,4})$/);
    if (m) { let y = +m[3]; if (y < 100) y += 2000; return new Date(y, +m[1] - 1, +m[2]); }
    m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
    if (m) return new Date(+m[1], +m[2] - 1, +m[3]);
    if (/^\d{5}$/.test(s)) return excelSerialToDate(+s);
    if (!/\d/.test(s) || (/[a-z]/i.test(s) && !/\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b/i.test(s))) return null;
    const t = Date.parse(s.match(/\d{4}/) ? s : `${s} ${today.getFullYear()}`);
    return isNaN(t) ? null : new Date(t);
  }
  function nextBusinessDay(d) { const r = new Date(d); do { r.setDate(r.getDate() + 1); } while (r.getDay() === 0 || r.getDay() === 6); return r; }

  function parseOwner(s) {
    s = clean(s);
    if (!s) return null;
    const o = { name: '', dob: '', pct: '' };
    const pm = s.match(/(\d{1,3}(?:\.\d+)?)\s*%/);
    if (pm) { o.pct = pm[1] + '%'; s = s.replace(pm[0], ' '); }
    const dm = s.match(/\b(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})\b/);
    if (dm) { o.dob = dm[1]; s = s.replace(dm[0], ' '); }
    o.name = clean(s.replace(/[\/|,;]+/g, ' '));
    return o;
  }

  function lookupClass(text, table) {
    const t = clean(text).toLowerCase();
    for (const line of String(table || '').split(/\n|;/)) {
      const [keys, code] = line.split('=').map(x => (x || '').trim());
      if (!code) continue;
      if (keys.split('|').some(k => k && t.includes(k.trim().toLowerCase()))) return code;
    }
    return '';
  }

  // ---------- build field values for the three forms ----------
  function buildValues(d, settingsIn, opts) {
    const S = Object.assign({}, DEFAULT_SETTINGS, settingsIn || {});
    const today = (opts && opts.today) || new Date();
    const custId = clean((opts && opts.customer_id) || '');
    const v125 = {}, v126 = {}, v130 = {}, v140 = {};
    const notes = [];

    const name = clean(d.client_name) + (clean(d.dba) ? ` DBA ${clean(d.dba)}` : '');
    const mail = parseAddress(d.mailing_address);
    const propAddr = /^(same|same as (mailing|above|mail)(ing)?( address)?|sam|ditto|n\/?a)\.?$/i.test(clean(d.property_address)) ? '' : clean(d.property_address);
    const premRaw = propAddr || clean(d.bldg1_address) || clean(d.mailing_address);
    const prem = parseAddress(premRaw);
    const email = fixEmail(d.email);
    if (email && email !== clean(d.email).replace(/\s/g, '')) notes.push(`Email corrected: ${clean(d.email)} → ${email}`);
    if (!mail.city && mail.raw) notes.push('Could not split the mailing address into street / city; please check it.');

    let eff = parseDateLoose(d.eff_date, today);
    if (!eff) { eff = nextBusinessDay(today); notes.push(`Effective date "${clean(d.eff_date) || 'blank'}" → used next business day ${fmtDate(eff)}.`); }
    if (d.eff_date_original != null && !parseDateLoose(d.eff_date_original, today) && clean(d.eff_date) && parseDateLoose(d.eff_date, today)) notes.push(`Effective date on the quote sheet was "${clean(d.eff_date_original) || 'blank'}" → using ${fmtDate(eff)}.`);
    let exp = parseDateLoose(d.exp_date, today);
    if (!exp) { exp = new Date(eff); exp.setFullYear(exp.getFullYear() + 1); }
    const effS = fmtDate(eff), expS = fmtDate(exp), todayS = fmtDate(today);

    const desc = clean(d.description), detail = clean(d.detailed_description);
    const opsText = [cap(desc), detail].filter(Boolean).join('. ');
    const yearStarted = parseInt(d.year_started, 10);
    const isNew = !yes(d.currently_insured) && (!yearStarted || yearStarted >= today.getFullYear());
    const insured = yes(d.currently_insured);
    const gross = parseMoney(d.gross_receipts);
    const pay = moneyRest(d.payroll); const payroll = parseMoney(pay.amount);
    const ft = clean(d.full_time), pt = clean(d.part_time);
    const fein = clean(d.tax_id);
    const ent = norm(d.entity_type);
    const entKey = /llc/.test(ent) ? 'llc' : /scorp|subch/.test(ent) ? 'subs' : /corp|inc/.test(ent) ? 'corp' : /part/.test(ent) ? 'partnership'
      : /trust/.test(ent) ? 'trust' : /joint|jv/.test(ent) ? 'jv' : /nonprofit|nfp/.test(ent) ? 'nfp' : /ind|sole|sp/.test(ent) ? 'individual' : (ent ? 'other' : '');
    const carrierPrice = clean(d.current_carrier_price);
    let curCarrier = '', curPrem = '';
    if (carrierPrice) { const p = carrierPrice.split(/\s*[\/|]\s*/); curCarrier = p[0]; curPrem = p.length > 1 ? money(parseMoney(p[1])) || p[1] : (parseMoney(p[0]) && !/[a-z]{3}/i.test(p[0]) ? money(parseMoney(p[0])) : ''); if (curPrem && p.length === 1) curCarrier = ''; }
    const owners = [d.owner1, d.owner2, d.owner3, d.owner4].map(parseOwner).filter(Boolean);
    const ais = [d.ai1, d.ai2, d.ai3, d.ai4].map(clean).filter(Boolean);
    const lossText = isNone(d.claims) ? (isNew ? 'new venture, no losses' : 'no losses') : clean(d.claims);

    // ---------------- ACORD 125 ----------------
    Object.assign(v125, {
      date: todayS,
      producer: [S.agency_name, S.agency_street, '', S.agency_city_state_zip].join('\n'),
      producer_contact: S.producer_name, producer_phone: S.producer_phone, producer_fax: S.producer_fax, producer_email: S.producer_email,
      cust_id: custId, eff_date: effS, exp_date: expS,
      ni1_name_address: [name, mail.street || mail.raw, '', cityLine(mail)].join('\n'),
      ni1_phone: clean(d.phone),
      c1_type: 'Owner', c1_name: clean(d.contact_name), c1_email: email, c1_phone1: clean(d.phone),
      primary_ops: opsText,
      date_started: yearStarted ? String(yearStarted) : '',
      producer_name: S.producer_name, producer_license: S.producer_license, national_producer: S.national_producer_number,
      loss1_desc: lossText,
    });
    if (entKey) v125[`ni1_ent_${entKey === 'individual' ? 'individual' : entKey}`] = true;
    if (isNone(d.claims)) v125.loss_none = true;
    const lob = norm(d.line_of_business);
    if (/gl|generalliab|cgl/.test(lob)) v125.lob_cgl = true;
    if (/bop|businessowner/.test(lob)) v125.lob_bop = true;
    if (/umb/.test(lob)) v125.lob_umbrella = true;
    if (/auto/.test(lob)) v125.lob_auto = true;
    if (/prop/.test(lob)) v125.lob_property = true;
    // premises (up to 4)
    const locs = [prem];
    [d.bldg2_address, d.bldg3_address].forEach(a => { if (clean(a)) locs.push(parseAddress(a)); });
    const sq = [d.bldg1_sqft, d.bldg2_sqft, d.bldg3_sqft];
    locs.forEach((a, i) => {
      const k = `loc${i + 1}_`;
      Object.assign(v125, { [k + 'num']: String(i + 1), [k + 'street']: a.street || a.raw, [k + 'city']: a.city, [k + 'state']: a.state, [k + 'zip']: a.zip });
      if (a.city || a.street) v125[k + 'inside'] = true;
      if (i === 0) { const it = norm(d.interest); if (/tenant|lease|rent/.test(it)) v125[k + 'tenant'] = true; else if (/own/.test(it)) v125[k + 'owner'] = true; }
      if (clean(sq[i])) v125[k + 'total_area'] = v125[k + 'occupied'] = money(parseMoney(sq[i])) || clean(sq[i]);
      if (i === 0) Object.assign(v125, { [k + 'ft']: ft, [k + 'pt']: pt, [k + 'revenue']: gross != null ? money(gross) : clean(d.gross_receipts), [k + 'desc']: opsText });
    });
    ['1a', '1b', '2', '3', '4', '5', '6', '7', '8', '9', '10', '12', '13', '14', '15'].forEach(q => v125['yn_' + q] = 'N');
    if (insured && (curCarrier || curPrem)) { v125.pc1_gl_carrier = curCarrier; v125.pc1_gl_premium = curPrem; v125.pc1_year = String(today.getFullYear()); }
    if (ais[0]) { v125.ai_name_address = ais[0]; v125.ai_additional_insured = true; }
    if (ais.length > 1) v125.remarks = 'Additional insureds: ' + ais.join('; ');

    // ---------------- ACORD 126 ----------------
    const glGross = clean(d.gl_gross_receipts != null ? d.gl_gross_receipts : d.gross_receipts);
    const classDesc = [cap(desc), detail, glGross ? `${glGross} gr` : '', pay.amount ? `${pay.amount} payroll` : '', pay.rest].filter(Boolean).join(', ');
    Object.assign(v126, {
      date: todayS, cust_id: custId, agency: S.agency_name, eff_date: effS, applicant: name,
      cgl: true, occurrence: true, per_policy: true,
      lim_gen_agg: S.gl_general_aggregate, lim_prod_agg: S.gl_products_aggregate, lim_pers_adv: S.gl_personal_adv,
      lim_each_occ: S.gl_each_occurrence, lim_fire_dmg: S.gl_damage_rented, lim_med_exp: S.gl_medical_expense,
      h1_loc: '1', h1_desc: classDesc,
      producer_name: S.producer_name, producer_license: S.producer_license, national_producer: S.national_producer_number,
    });
    for (let i = 1; i <= 6; i++) v126['yn_con' + i] = 'N';
    for (let i = 1; i <= 10; i++) v126['yn_prod' + i] = 'N';
    for (let i = 1; i <= 22; i++) v126['yn_gi' + i] = 'N';
    if (clean(d.subout)) { const so = parseMoney(d.subout); v126.sub_paid = so != null ? '$' + money(so) : clean(d.subout); }
    if (ais[0]) { v126.ai_name_address = ais[0]; v126.ai_additional_insured = true; }

    // ---------------- ACORD 130 ----------------
    const yrs = !yearStarted || yearStarted >= today.getFullYear() ? 'new' : String(today.getFullYear() - yearStarted);
    const state = prem.state || mail.state || 'CA';
    Object.assign(v130, {
      date: todayS,
      agency: [S.agency_name, S.agency_street, '', S.agency_city_state_zip].join('\n'),
      producer_name: S.producer_name, producer_phone: S.producer_phone, producer_fax: S.producer_fax, producer_email: S.producer_email,
      cust_id: custId, applicant: name, office_phone: clean(d.phone), mobile_phone: clean(d.phone),
      mailing_address: [mail.street || mail.raw, '', cityLine(mail)].join('\n'),
      yrs_in_bus: yrs, email, fein, st_quote: true,
      eff_date: effS, exp_date: expS, part1_states: state,
      el_each_accident: S.wc_each_accident, el_policy_limit: S.wc_policy_limit, el_each_employee: S.wc_each_employee,
      contact_inspection_name: clean(d.contact_name), contact_inspection_mobile: clean(d.phone), contact_inspection_email: email,
      sheet_num: '1', sheet_of: '1', rating_state: state,
      nature_of_business: opsText + (isNew ? '. New business.' : '') ,
      sign_date: todayS, national_producer: S.national_producer_number,
    });
    if (entKey) v130['ent_' + ({ individual: 'sole', nfp: 'other' }[entKey] || entKey)] = true;
    locs.forEach((a, i) => { v130[`loc${i + 1}_num`] = String(i + 1); v130[`loc${i + 1}_address`] = fullAddr(a) || a.raw; });
    owners.forEach((o, i) => Object.assign(v130, {
      [`ind${i + 1}_state`]: state, [`ind${i + 1}_loc`]: '1', [`ind${i + 1}_name`]: o.name, [`ind${i + 1}_dob`]: o.dob,
      [`ind${i + 1}_title`]: 'owner', [`ind${i + 1}_own`]: o.pct, [`ind${i + 1}_incexc`]: 'exc',
    }));
    // rating worksheet
    let codes = [d.class_code1, d.class_code2, d.class_code3, d.class_code4].map(clean).filter(Boolean);
    if (!codes.length) {
      const c = lookupClass(`${desc} ${detail}`, S.wc_class_lookup);
      if (c) { codes = [c]; notes.push(`WC class code ${c} picked from the description (no class code on the quote sheet).`); }
      else notes.push('No WC class code on the quote sheet; fill it in on the 130 page 2.');
    }
    if (!codes.length) codes = [''];
    codes.forEach((c, i) => {
      const m = c.match(/^(\d{4})\s*[-–:]?\s*(.*)$/);
      Object.assign(v130, {
        [`r${i + 1}_loc`]: '1', [`r${i + 1}_class`]: m ? m[1] : c,
        [`r${i + 1}_desc`]: (m && m[2]) ? cap(m[2]) : cap(desc),
      });
      if (i === 0) Object.assign(v130, { r1_ft: ft, r1_pt: pt, r1_payroll: payroll != null ? money(payroll) : '' });
    });
    if (insured && (curCarrier || curPrem)) { v130.pc1_co = curCarrier; v130.pc1_premium = curPrem; v130.pc1_year = String(today.getFullYear()); }
    else v130.pc1_co = isNew ? 'none, new venture' : 'none';
    for (let i = 1; i <= 24; i++) v130['yn_' + i] = 'No';

    // ---------------- ACORD 140 ----------------
    const amt = x => { x = clean(x); const n = parseMoney(x); return n != null && /^\$?[\d,.]+\s*(k|m|mil)?$/i.test(x) ? '$' + money(n) : x; };
    Object.assign(v140, {
      date: todayS, agency: S.agency_name, eff_date: effS, named_insured: name,
      prem_num: '1', bldg_num: '1', street: fullAddr(prem) || prem.raw, bldg_desc: clean(d.p_bldg_desc),
      construction: clean(d.bldg1_construction), hydrant: clean(d.p_hydrant), station: clean(d.p_station),
      stories: clean(d.p_stories), basements: clean(d.p_basements), yr_built: clean(d.bldg1_year_built),
      total_area: clean(d.bldg1_sqft) ? (money(parseMoney(d.bldg1_sqft)) || clean(d.bldg1_sqft)) : '',
      roof_type: clean(d.bldg1_roof),
      wiring_yr: clean(d.p_wiring_yr), roofing_yr: clean(d.p_roof_yr), plumbing_yr: clean(d.p_plumbing_yr), heating_yr: clean(d.p_heating_yr),
      imp_wiring: !!clean(d.p_wiring_yr), imp_roofing: !!clean(d.p_roof_yr), imp_plumbing: !!clean(d.p_plumbing_yr), imp_heating: !!clean(d.p_heating_yr),
      exp_right: clean(d.p_exp_right), exp_left: clean(d.p_exp_left), exp_front: clean(d.p_exp_front), exp_rear: clean(d.p_exp_rear),
      burglar_type: clean(d.p_burglar), fire_protection: clean(d.p_fire_prot),
      ai_name_address: ais[0] || '',
      sign_date: todayS, producer_name: '', producer_license: S.producer_license, national_producer: S.national_producer_number,
    });
    [1, 2, 3].forEach(i => { if (clean(d['p_subj' + i]) || clean(d['p_amt' + i])) { v140[`s${i}_subject`] = clean(d['p_subj' + i]); v140[`s${i}_amount`] = amt(d['p_amt' + i]); } });
    if (clean(d.bldg2_address)) { const a2 = parseAddress(d.bldg2_address); Object.assign(v140, { p2_prem_num: '2', p2_bldg_num: '1', p2_street: fullAddr(a2) || a2.raw }); }

    return { '125': v125, '126': v126, '130': v130, '140': v140, notes };
  }

  // ---------- fill a template with pdf-lib ----------
  async function fillPdf(templateBytes, form, values, PDFLibIn) {
    const L = PDFLibIn || root.PDFLib;
    const doc = await L.PDFDocument.load(templateBytes);
    const f = doc.getForm();
    const helv = await doc.embedFont(L.StandardFonts.Helvetica);
    const byName = {};
    for (const fld of f.getFields()) byName[fld.getName()] = fld;
    for (const [k, val] of Object.entries(values)) {
      if (val === '' || val == null || val === false) continue;
      const re = new RegExp(`^a${form}_p\\d+_${k}$`);
      const targets = Object.keys(byName).filter(n => n === `a${form}_${k}` || re.test(n));
      for (const n of targets) {
        const fld = byName[n];
        if (fld instanceof L.PDFCheckBox) { if (val) fld.check(); continue; }
        if (!(fld instanceof L.PDFTextField)) continue;
        const text = String(val).replace(/[^\x0A\x20-\x7E\xA0-\xFF–—‘’“”•]/g, '');
        const w = fld.acroField.getWidgets()[0];
        const r = w.getRectangle();
        let size = (fld.acroField.getDefaultAppearance() || '').match(/([\d.]+)\s+Tf/); size = size ? parseFloat(size[1]) : 10;
        if (!fld.isMultiline()) {
          while (size > 6 && helv.widthOfTextAtSize(text, size) > r.width - 4) size -= 0.5;
          size = Math.min(size, Math.max(6, r.height - 2));
        } else {
          const lines = text.split('\n');
          const est = () => lines.reduce((a, ln) => a + Math.max(1, Math.ceil(helv.widthOfTextAtSize(ln, size) / (r.width - 6))), 0) * size * 1.17;
          while (size > 6 && est() > r.height - 2) size -= 0.5;
        }
        fld.setText(text);
        fld.setFontSize(size);
      }
    }
    f.updateFieldAppearances(helv);
    return await doc.save();
  }

  // ---------- combine filled PDFs into one, keeping the fields fillable ----------
  async function mergePdfs(list, PDFLibIn) {
    const L = PDFLibIn || root.PDFLib;
    const out = await L.PDFDocument.create();
    const fieldRefs = [];
    for (const bytes of list) {
      const src = await L.PDFDocument.load(bytes);
      const pages = await out.copyPages(src, src.getPageIndices());
      for (const p of pages) {
        out.addPage(p);
        const annots = p.node.Annots();
        if (!annots) continue;
        for (let i = 0; i < annots.size(); i++) {
          const ref = annots.get(i);
          const dict = out.context.lookup(ref);
          if (dict && dict.get(L.PDFName.of('T'))) fieldRefs.push(ref);
        }
      }
    }
    const acroDict = out.context.obj({ Fields: fieldRefs, DA: L.PDFString.of('/Helv 0 Tf 0 g') });
    const helv = out.context.obj({ Type: 'Font', Subtype: 'Type1', BaseFont: 'Helvetica', Encoding: 'WinAnsiEncoding' });
    const zadb = out.context.obj({ Type: 'Font', Subtype: 'Type1', BaseFont: 'ZapfDingbats' });
    acroDict.set(L.PDFName.of('DR'), out.context.obj({ Font: { Helv: out.context.register(helv), ZaDb: out.context.register(zadb) } }));
    out.catalog.set(L.PDFName.of('AcroForm'), out.context.register(acroDict));
    return await out.save();
  }

  // Review screen sections: each answer appears once, in the first form that uses it.
  const SECTIONS = [
    ['ACORD 125 – Applicant (also used on the 126 and 130)', [
      // same order as the boxes appear on the 125: lines of business, policy dates, applicant, contact,
      // premises, nature of business, additional interest, prior carrier, loss history
      'line_of_business', 'eff_date', 'exp_date',
      'client_name', 'dba', 'mailing_address', 'phone', 'entity_type',
      'contact_name', 'email',
      'property_address', 'interest', 'full_time', 'part_time', 'gross_receipts',
      'bldg1_address', 'bldg1_sqft', 'bldg2_address', 'bldg2_sqft', 'bldg3_address', 'bldg3_sqft',
      'year_started', 'description', 'detailed_description',
      'ai1', 'ai2', 'ai3', 'ai4',
      'currently_insured', 'current_carrier_price',
      'claims']],
    ['ACORD 126 – General Liability', ['gl_gross_receipts', 'payroll', 'subout']],
    ['ACORD 130 – Workers Comp (also uses payroll from the 126 section)', ['tax_id', 'owner1', 'owner2', 'owner3', 'owner4', 'class_code1', 'class_code2', 'class_code3', 'class_code4']],
    ['ACORD 140 – Property (also uses address, building sq ft and additional insured from the 125 section)', ['bldg1_year_built', 'bldg1_construction', 'bldg1_roof', 'p_bldg_desc', 'p_subj1', 'p_amt1', 'p_subj2', 'p_amt2', 'p_subj3', 'p_amt3', 'p_hydrant', 'p_station', 'p_stories', 'p_basements', 'p_wiring_yr', 'p_roof_yr', 'p_plumbing_yr', 'p_heating_yr', 'p_exp_right', 'p_exp_left', 'p_exp_front', 'p_exp_rear', 'p_burglar', 'p_fire_prot']],
    ['Other quote sheet info (not on these forms)', ['years_experience', 'lead_date', 'lead_source']],
  ];
  // Turn "asap"/blank into a real effective date and set expiration to one year later (for the review screen)
  function resolveDates(d, today) {
    today = today || new Date();
    let eff = parseDateLoose(d.eff_date, today);
    const note = eff ? '' : `Effective date "${clean(d.eff_date) || 'blank'}" → next business day.`;
    if (!eff) eff = nextBusinessDay(today);
    const exp = new Date(eff); exp.setFullYear(exp.getFullYear() + 1);
    return { eff: fmtDate(eff), exp: fmtDate(exp), note };
  }
  function addYear(effText, today) {
    const e = parseDateLoose(effText, today || new Date());
    if (!e) return '';
    const x = new Date(e); x.setFullYear(x.getFullYear() + 1); return fmtDate(x);
  }
  const api = { parseQuotePdfFields, resolveDates, addYear, DEFAULT_SETTINGS, DATA_FIELDS, SECTIONS, mergePdfs, parseQuoteSheet, buildValues, fillPdf, parseAddress, parseOwner, parseMoney, fmtDate };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.AcordCore = api;
})(typeof window !== 'undefined' ? window : globalThis);
