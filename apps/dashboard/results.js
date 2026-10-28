/* Result presentation uses stored assessments; historical results are never reclassified. */
function renderScan(s,staff=false,report=null){
  const r=s.result;
  const status=s.status.replaceAll('_',' ');
  let html=`<div class="overline">${esc(s.kind.toUpperCase())} SCAN · ${date(s.created)}</div>
    <h2>Inside the evidence.</h2>
    <div class="result-state" aria-label="Assessment and processing status">
      <div class="result-state-item"><span class="state-label">Assessment</span> ${badge(r.assessment||'Pending')}</div>
      <div class="result-state-item"><span class="state-label">Processing</span> <span class="processing-status">${esc(status[0].toUpperCase()+status.slice(1))}</span></div>
    </div>`;
  if(['queued','processing'].includes(s.status)){
    html+='<div class="loading">Your scan is in the processing queue…<p>Keep this view open to receive the result.</p></div>';
  }else if(['awaiting_confirmation','partially_completed'].includes(s.status)){
    html+=`<div class="notice">${esc(r.error||r.message)}</div><form id="confirm-form"><label>Review and correct the extracted text<textarea id="corrected" required maxlength="20000">${esc(s.text)}</textarea></label><button class="primary">Confirm text & analyze ↗</button></form>`;
  }else if(s.status==='failed'){
    html+=`<div class="inline-error">${esc(r.error)}</div>`;
  }else{
    const title=r.assessment==='Inconclusive'?'Inconclusive assessment':`${esc(r.assessment)} risk assessment`;
    html+=`<section class="result-summary"><h2>${title}</h2><p>${esc(r.explanation)}</p><small>Indicator score: ${esc(r.score)}/100 · Not a probability</small></section>
      <h3>Original message & evidence</h3><blockquote>${highlighted(s.text,r.evidence||[])}</blockquote>
      ${renderUrlDetails(r.url_details,s.kind)}
      ${r.model_mode?`<section class="model-results"><h3>Model predictions</h3><p>${esc(r.model_mode)}</p>${(r.models||[]).map(m=>`<article><b>${esc(m.kind)}: ${esc(m.prediction)}</b><p>${esc(m.version)} · ${esc(m.effect)}</p><p>${esc(m.conflict||m.scope)}</p></article>`).join('')}<p>Model predictions are separate from highlighted rules evidence. A spam or ham prediction does not establish safety or fraud.</p></section>`:''}
      <div class="evidence-list">${(r.evidence||[]).map(e=>`<article class="evidence-item"><h3 class="evidence-title">${esc(e.description)}</h3><blockquote class="evidence-quote"><mark>${esc(e.quote)}</mark></blockquote><p class="evidence-weight">Indicator weight: +${esc(e.weight)} · Counted once per signal</p></article>`).join('')||'<p>No configured indicators were established. This is not verified safety.</p>'}</div>
      ${(r.context_notes||[]).map(note=>`<div class="notice">${esc(note)}</div>`).join('')}
      <h3 style="margin-top:24px">Suggested next steps</h3><ul>${(r.next_actions||[]).map(t=>`<li>${esc(t)}</li>`).join('')}</ul>
      <div class="notice"><b>Analysis coverage</b><br>Completed: ${esc((r.coverage?.completed||[]).join(', ')||'None')}<br>Failed: ${esc((r.coverage?.failed||[]).join(', ')||'None recorded')}<br>Unavailable: ${esc((r.coverage?.unavailable||[]).join(', ')||'None recorded')}</div>
      <small class="analysis-version">${esc(r.version)} · ${r.analyzed_at?new Date(r.analyzed_at*1000).toLocaleString():''}</small>`;
    if(s.reviews?.length){
      html+=`<h3 style="margin-top:24px">Analyst reviews</h3>${s.reviews.map(v=>`<div class="notice"><b>${esc(v.verdict)}</b><br>${esc(v.reason)}<br><small>${date(v.created)}</small></div>`).join('')}`;
    }
    if(!staff)html+=`<div class="action-row"><button class="secondary" id="feedback">Result looks wrong?</button><button class="secondary" id="report" ${s.report_id?'disabled':''}>${s.report_id?'Submitted for review':'Request analyst review'}</button></div>`;
  }
  if(staff){
    html+=`<div class="notice">User’s review request: ${esc(report.reason)}</div><form id="review-form"><label>Analyst decision<select id="verdict"><option>Confirmed scam</option><option>Legitimate</option><option>Uncertain</option></select></label><label>Evidence and reasoning<textarea id="review-reason" minlength="3" maxlength="2000" required></textarea></label><button class="primary">Record review ↗</button></form>`;
  }else html+='<div class="action-row"><button class="text danger" id="delete-scan">Delete this scan</button></div>';
  modal(html);
  if($('#confirm-form'))$('#confirm-form').onsubmit=guarded(async e=>{
    e.preventDefault();await api('/scans/'+s.id+'/confirm',{method:'POST',body:{kind:'text',text:$('#corrected').value}});await showScan(s.id);
  });
  if($('#feedback'))$('#feedback').onclick=()=>comment(s,'feedback');
  if($('#report'))$('#report').onclick=()=>comment(s,'report');
  if($('#delete-scan'))$('#delete-scan').onclick=()=>{
    modal('<h2>Delete this scan?</h2><p>The message, screenshot, feedback and reports will be removed.</p><button id="delete-confirm" class="primary">Delete scan</button>');
    $('#delete-confirm').onclick=guarded(async()=>{await api('/scans/'+s.id,{method:'DELETE'});$('#modal').close();await route();toast('Scan deleted')});
  };
  if($('#review-form'))$('#review-form').onsubmit=guarded(async e=>{
    e.preventDefault();await api('/reports/'+report.id+'/decision',{method:'POST',body:{verdict:$('#verdict').value,reason:$('#review-reason').value}});$('#modal').close();toast('Analyst decision recorded');await queue();
  });
}

function renderUrlDetails(details,kind){
  if(!details?.length)return kind==='url'?'<p>URL detail fields were not stored for this historical scan. This does not imply safety.</p>':'';
  return `<section class="url-details"><h3>URL destination details</h3><p>Links are displayed as text. No destination was opened. HTTPS is not proof of safety.</p>${details.map(detail=>`<article class="url-card">
    <code class="url-value" dir="ltr">${esc(detail.url)}</code>
    <dl><dt>Actual hostname</dt><dd class="actual-hostname">${esc(detail.hostname||'Unavailable: URL parsing failed')}</dd>
    <dt>Registrable domain (PSL)</dt><dd class="registrable-domain">${esc(detail.registrable_domain||detail.registrable_domain_note||'Unavailable')}</dd>
    ${detail.unicode_hostname&&detail.unicode_hostname!==detail.hostname?`<dt>Unicode hostname</dt><dd>${esc(detail.unicode_hostname)}</dd>`:''}
    <dt>Subdomain</dt><dd>${esc(detail.subdomain||'None identified / unavailable')}</dd>
    <dt>User information before @</dt><dd class="user-information">${esc(detail.user_information_present?detail.user_information:'None')}</dd></dl>
    ${detail.user_information_note?`<p>${esc(detail.user_information_note)}</p>`:''}
    <div class="url-checks"><p><b>Completed:</b> ${esc((detail.checks?.completed||[]).join(', ')||'None')}</p><p><b>Failed:</b> ${esc((detail.checks?.failed||[]).join(', ')||'None recorded')}</p><p><b>Unavailable:</b> ${esc((detail.checks?.unavailable||[]).join(', ')||'None recorded')}</p></div>
    <small>${esc(detail.psl?.library||'PSL')} ${esc(detail.psl?.version||'')} · Offline snapshot · No DNS/reputation checks</small>
  </article>`).join('')}</section>`;
}
