// same-origin whenever served over http(s); only fall back when opened as a file://
const API = location.protocol.startsWith("http")
  ? "" : (localStorage.getItem("AEGIS_API") || "http://localhost:5757");

function setSteps(on){document.querySelectorAll('#steps .s').forEach(s=>
  s.classList.toggle('on', on));}

function toggleSource(){
  const cfg=document.getElementById('source').value==='config_import';
  document.getElementById('intent').style.display=cfg?'none':'';
  document.getElementById('configText').style.display=cfg?'':'none';
  document.getElementById('vendor').style.display=cfg?'':'none';
  // config-import skips the LLM, so the "generate (LLM)" step is greyed out
  const gen=document.querySelector('#steps .s[data-k="generate"]');
  if(gen) gen.style.opacity=cfg?'0.35':'';
}

function modeHint(){
  const live=document.getElementById('mode').value==='live';
  document.getElementById('foot').textContent = live
    ? 'live = operator / air-gapped path — needs an API key + self-hosted LLM + containerlab. For a zero-deps run, use sim.'
    : '';
}

function apiHeaders(){
  const h={"Content-Type":"application/json"};
  const k=(document.getElementById('apiKey').value||sessionStorage.getItem('aegisKey')||'').trim();
  if(k) h["X-Aegis-Key"]=k;
  const p=(document.getElementById('personalKey').value||sessionStorage.getItem('aegisPersonalKey')||'').trim();
  if(p) h["X-Aegis-Approver-Key"]=p;
  return h;
}

async function runPreflight(){
  const btn=document.getElementById('go'); btn.disabled=true;
  setSteps(true);
  document.getElementById('foot').textContent='running…';
  const source=document.getElementById('source').value;
  const body={
    source:source,
    lab:document.getElementById('lab').value,
    mode:document.getElementById('mode').value,
    frameworks:["pci_dss_v4","disa_stig","cis_v8","nist_csf_2.0","nist_800-53","nist_800-171",
                "soc2","nerc_cip","hipaa","iso_27001","iec_62443"]
    // no approver here on purpose: approval is a separate person + HMAC token at promotion
  };
  const ref=document.getElementById('changeRef').value.trim();
  if(ref) body.change_ref=ref;
  if(source==='config_import'){
    body.config=document.getElementById('configText').value;
    body.vendor=document.getElementById('vendor').value;
    body.device='imported-1';
  } else {
    body.intent=document.getElementById('intent').value;
  }
  try{
    const r=await fetch(API+"/api/preflight/run",{method:"POST",
      headers:apiHeaders(),body:JSON.stringify(body)});
    const data=await r.json();
    if(!r.ok){render_err(data);} else {render(data);}
  }catch(e){render_err({error:String(e),stage:"network"});}
  finally{btn.disabled=false; setSteps(false);}
}

function render_err(d){
  // Live mode is the operator / air-gapped path: it spawns a containerlab twin and
  // calls a self-hosted LLM, so the same-origin browser demo can't drive it (no API
  // key, and the host needs the model + clab). Rather than dead-end on a bare
  // "unauthorized", explain it and point at the sim demo that runs the full loop here.
  const liveGated = d.mode==='live' &&
    /unauthorized|not configured|not available|guard/i.test((d.error||'')+' '+(d.stage||''));
  if(liveGated){
    document.getElementById('c-verdict').innerHTML=
      '<h3>Verdict</h3>'+
      '<div class="muted" style="font-size:15px;line-height:1.5">'+
      '<b style="color:var(--ink)">Live mode is operator-only.</b><br>'+
      'It clones a <b>containerlab</b> digital twin and calls a <b>self-hosted LLM</b>, so it needs '+
      'an operator API key plus the model + containerlab on the host — not the browser demo.</div>'+
      '<div class="kv"><span>this run</span><b>'+h(d.error||'gated')+'</b></div>'+
      '<div class="kv"><span>fix</span><b>switch mode → <span style="color:var(--acc)">sim</span></b></div>';
    const note={'c-twin':'Digital twin','c-config':'Generated config (grounded)',
                'c-evidence':'Evidence &amp; compliance'};
    for(const id in note)
      document.getElementById(id).innerHTML='<h3>'+note[id]+
        '</h3><div class="muted">— sim mode runs the full pipeline offline, right here</div>';
    document.getElementById('foot').textContent=
      'live = air-gapped operator path · the open demo is sim (zero deps, nothing leaves the box)';
    return;
  }
  document.getElementById('c-verdict').innerHTML=
    '<h3>Verdict</h3><div class="err">✕ '+h(d.error||'request failed')+
    '</div><div class="muted">stage: '+h(d.stage||'?')+
    (d.mode?' · mode: '+h(d.mode):'')+'</div>';
  // clear stale panels so a failed run never shows a previous run's data
  const blanks={'c-twin':'Digital twin','c-config':'Generated config (grounded)',
                'c-evidence':'Evidence &amp; compliance'};
  for(const id in blanks)
    document.getElementById(id).innerHTML='<h3>'+blanks[id]+
      '</h3><div class="muted">— run did not complete</div>';
  document.getElementById('foot').textContent='';
}

let LAST_BUNDLE=null;
async function downloadPdf(){
  if(!LAST_BUNDLE) return;
  const r=await fetch(API+"/api/preflight/evidence/pdf",{method:"POST",
    headers:apiHeaders(),body:JSON.stringify(LAST_BUNDLE)});
  if(!r.ok){alert("PDF failed: "+(await r.text()));return;}
  const blob=await r.blob();
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download="aegis-evidence-"+(LAST_BUNDLE.run_id||"bundle").slice(0,12)+".pdf";
  a.click(); URL.revokeObjectURL(a.href);
}
function render(b){
  LAST_BUNDLE=b;
  const dec=b.verdict.decision;
  // cls is gated to a fixed allow-list of class names — never raw bundle text.
  const cls=dec==='ship_ready'?'ship':dec==='blocked'?'block':'appr';
  const label=h(String(dec).replace('_',' ').toUpperCase());
  document.getElementById('c-verdict').innerHTML=
    '<h3>Verdict</h3>'+
    '<div class="verdict '+cls+'"><span class="dot"></span>'+label+'</div>'+
    '<div class="muted" style="margin-top:8px">'+h(b.verdict.reason)+'</div>'+
    '<div class="kv"><span>risk tier</span><b>'+h(b.change.risk_tier)+'</b></div>'+
    '<div class="kv"><span>blast radius</span><b>'+
      h(b.validation.blast_radius.severity)+' · '+
      h(b.validation.blast_radius.devices_affected)+' device(s)</b></div>'+
    '<div class="kv"><span>approval required</span><b>'+
      (b.change.approval.required?('yes — '+h(b.change.approval.granted_by||'PENDING')):'no')+
      '</b></div>';

  const t=b.twin;
  document.getElementById('c-twin').innerHTML=
    '<h3>Digital twin · '+h(t.topology)+'</h3>'+
    '<div class="kv"><span>engine</span><b>'+h(t.engine)+'</b></div>'+
    '<div class="kv"><span>nodes</span><b>'+h(t.node_count)+'</b></div>'+
    '<div class="kv"><span>converged</span><b>'+(t.converged?'✔ yes':'✕ no')+'</b></div>'+
    '<div class="kv"><span>convergence</span><b>'+h(t.convergence_sec)+'s</b></div>'+
    '<div class="kv"><span>BGP sessions</span><b>'+
      h(t.bgp_sessions.before)+' → '+h(t.bgp_sessions.after)+
      (t.bgp_sessions.after<t.bgp_sessions.before?' ⚠':'')+'</b></div>'+
    '<div class="dev">routes +'+h(b.validation.state_diff.routes_added.length)+
      ' / -'+h(b.validation.state_diff.routes_removed.length)+
      ' · sessions dropped: '+h(b.validation.state_diff.sessions_dropped.join(', ')||'none')+'</div>';

  document.getElementById('c-config').innerHTML='<h3>Generated config (grounded)</h3>'+
    b.change.generated_configs.map(c=>
      '<div class="dev">'+h(c.device)+' · '+h(c.vendor)+'</div>'+
      '<pre>'+h(c.config)+'</pre>'+
      '<div class="dev">grounded: '+h(c.grounded_commands.join(' · ')||'—')+'</div>'
    ).join('');

  const bf=b.validation.batfish;
  document.getElementById('c-evidence').innerHTML='<h3>Evidence &amp; compliance</h3>'+
    '<div class="kv"><span>batfish</span><b>'+h(bf.errors)+' err · '+h(bf.warnings)+
      ' warn · '+h(bf.passed)+' pass</b></div>'+
    '<div style="margin:8px 0">'+
      b.validation.compliance.map(x=>{
        const cls=x.status==='fail'?'fail':x.status==='not_applicable'?'na':'pass';
        const lbl=x.status==='not_applicable'?'n/a':x.status;
        return '<span class="chip '+cls+'">'+h(x.framework)+' '+h(x.control)+
          ' · '+h(lbl)+'</span>';}).join('')+'</div>'+
    (bf.findings.length?'<pre>'+h(bf.findings.join('\n'))+'</pre>':'')+
    '<div class="dev">rollback steps: '+h(b.rollback.plan.length)+
      ' · tested in twin: '+(b.rollback.tested_in_twin?'yes':'no')+'</div>'+
    '<div style="margin-top:12px"><button id="pdfBtn" type="button" '+
      'style="background:transparent;border:1px solid var(--acc);color:var(--acc);'+
      'font-weight:600">⬇ Download evidence PDF</button></div>';

  renderIntents(b.validation.intents);

  document.getElementById('foot').innerHTML=
    'run '+h(b.run_id)+' · '+h(b.created_utc)+' · generated_by '+h(b.integrity.generated_by)+
    ' · egress '+h(b.integrity.egress)+'<br>sha256 '+h(b.integrity.sha256);
}
// v1.4 intent checks: before → after per intent; error is shown as a failure, never a pass.
// Built with DOM nodes + textContent (no HTML strings), so no intent field can become markup.
function renderIntents(ir){
  if(!ir) return;
  const el=(tag,cls,text)=>{const n=document.createElement(tag);
    if(cls) n.className=cls; if(text!=null) n.textContent=String(text); return n;};
  const wrap=el('div');
  const kv=el('div','kv');
  kv.append(el('span',null,'intents ('+ir.engine+')'),
            el('b',null,ir.failed+' fail · '+ir.errors+' n/e · '+ir.regressions+' regression'));
  const chips=el('div','intent-chips');
  (ir.results||[]).forEach(r=>{
    const c=el('span','chip '+(r.status==='pass'?'pass':'fail'),
      r.id+' · '+(r.before||'—')+'→'+r.status+(r.regression?' ⚠':''));
    c.title=String(r.evidence||'');
    chips.append(c);
  });
  wrap.append(kv,chips);
  const card=document.getElementById('c-evidence');
  card.insertBefore(wrap, card.querySelector('.dev'));
}

// Escape every HTML-significant char so server/LLM-derived values can never break
// out of the markup they are injected into. h() coerces null/number/etc. to a string
// first so callers can pass any field value straight through.
function escapeHtml(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>(
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
const h=escapeHtml;

// CSP: script-src 'self' (no 'unsafe-inline') — wire handlers here, never in markup.
document.getElementById('source').addEventListener('change', toggleSource);
document.getElementById('mode').addEventListener('change', modeHint);
document.getElementById('go').addEventListener('click', runPreflight);
document.getElementById('apiKey').addEventListener('change',
  e => sessionStorage.setItem('aegisKey', e.target.value));
document.getElementById('personalKey').addEventListener('change',
  e => sessionStorage.setItem('aegisPersonalKey', e.target.value));
document.addEventListener('click', e => {
  if (e.target && e.target.id === 'pdfBtn') downloadPdf();
});
