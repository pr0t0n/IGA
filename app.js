const state = {
  token: localStorage.getItem('nexo.session') || '',
  user: null,
  credentials: [],
  risks: [],
  audit: []
};

const modules = {
  identidades: { eyebrow:'IDENTITY INVENTORY', title:'Inventário de identidades', desc:'Identidades coletadas diretamente dos ambientes conectados.' },
  projetos: { eyebrow:'ACCESS INVENTORY', title:'Visão por projeto e recurso', desc:'Identidades, roles, privilégios e riscos agrupados por escopo real.' },
  roles: { eyebrow:'ACCESS INVENTORY', title:'Visão por role', desc:'Impacto, alcance e criticidade das funções concedidas nos ambientes.' },
  contas: { eyebrow:'IDENTITY INVENTORY', title:'Visão por conta', desc:'Contas humanas e não humanas correlacionadas aos seus acessos e riscos.' },
  acessos: { eyebrow:'ACCESS INVENTORY', title:'Inventário de acessos', desc:'Concessões coletadas diretamente dos provedores cloud.' },
  riscos: { eyebrow:'ACCESS INTELLIGENCE · ACCESS RISK', title:'Inteligência e riscos', desc:'Achados calculados após uma análise real do ambiente.' },
  privilegiados: { eyebrow:'PRIVILEGED ACCESS', title:'Acesso privilegiado', desc:'Privilégios encontrados nas integrações analisadas.' },
  ueba: { eyebrow:'UEBA', title:'Anomalias de acesso', desc:'Anomalias produzidas a partir dos eventos coletados.' },
  compliance: { eyebrow:'COMPLIANCE AUDIT', title:'Conformidade e revisões', desc:'Controles avaliados sobre dados efetivamente coletados.' }
};

async function api(path, options={}){
  const response=await fetch(`/api${path}`,{headers:{'Content-Type':'application/json',...(state.token?{Authorization:`Bearer ${state.token}`}:{ }),...(options.headers||{})},...options});
  if(response.status===204)return null;
  const body=await response.json().catch(()=>({detail:'Resposta inválida do servidor'}));
  if(response.status===401&&path!=='/auth/login'){showLogin();throw new Error('Sua sessão expirou. Entre novamente.')}
  if(!response.ok){const detail=typeof body.detail==='string'?body.detail:(body.detail?.errors||['Não foi possível concluir a operação.']).join(' ');throw new Error(detail)}
  return body;
}
function providerClass(p){ return p.toLowerCase(); }
function formatDate(value){return value&&value!=='Nunca'?new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short'}).format(new Date(value)):'Nunca'}
function renderRisks(){
  document.querySelector('#priority-risks').innerHTML = state.risks.length?state.risks.map(r => `<div class="risk-row"><i class="severity ${r.type}"></i><div><strong>${escapeHtml(r.title)}</strong><small>${escapeHtml(r.meta)}</small></div>${r.id?`<button class="badge ${r.type}" onclick="resolveFinding(${r.id})" title="Tratar risco">${escapeHtml(r.level)} · Tratar</button>`:`<span class="badge ${r.type}">${escapeHtml(r.level)}</span>`}</div>`).join(''):'<div class="chart-empty">Nenhum risco identificado.</div>';
}
function renderClouds(){
  document.querySelector('#cloud-summary').innerHTML = state.credentials.map(c => `<div class="cloud-item"><span class="cloud-logo ${providerClass(c.provider)}">${c.provider}</span><div><strong>${escapeHtml(c.name)}</strong><small>${escapeHtml(c.scope)}</small></div><span class="cloud-status">● ${escapeHtml(c.status)}</span></div>`).join('');
}
function renderCredentials(query=''){
  const filtered=state.credentials.filter(c=>`${c.name} ${c.provider} ${c.scope}`.toLowerCase().includes(query.toLowerCase()));
  document.querySelector('#credential-count').textContent=`${filtered.length} integrações`;
  document.querySelector('#credentials-body').innerHTML=filtered.map(c=>`<tr><td><div class="integration-cell"><span class="cloud-logo ${providerClass(c.provider)}">${c.provider}</span><div><strong>${escapeHtml(c.name)}</strong><small>ID ${String(c.id).padStart(4,'0')}</small></div></div></td><td>${c.provider}</td><td>${escapeHtml(c.scope)}</td><td>${formatDate(c.lastSyncedAt)}</td><td><span class="status-pill">● ${escapeHtml(c.status)}</span></td><td class="row-actions">${state.user?.role==='auditor'?'Somente leitura':`<button onclick="scanCredential(${c.id},this)">Analisar</button><button onclick="editCredential(${c.id})">Editar</button><button class="delete" onclick="deleteCredential(${c.id})">Remover</button>`}</td></tr>`).join('') || '<tr><td colspan="6">Nenhuma credencial cadastrada. Use “Adicionar credencial” para conectar um ambiente.</td></tr>';
  renderClouds();
}
function renderAudit(filter='all'){
  const events=state.audit.filter(e=>filter==='all'||e.type===filter);
  document.querySelector('#audit-timeline').innerHTML=events.length?events.map(e=>`<div class="event"><div class="event-time">${e.date}</div><div class="event-line"><i></i></div><div class="event-content"><strong>${escapeHtml(e.title)}</strong><p>${escapeHtml(e.text)}</p><small>${escapeHtml(e.actor)}</small></div></div>`).join(''):'<div class="chart-empty">Nenhum evento de auditoria registrado.</div>';
}
function renderModules(){
  Object.entries(modules).forEach(([id,m])=>{
    document.querySelector(`#${id}`).innerHTML=`<div class="module-hero"><p class="eyebrow">${m.eyebrow}</p><h1>${m.title}</h1><p>${m.desc}</p></div>`;
  });
}
function navigate(page){
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id===page));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===page));
  window.scrollTo({top:0,behavior:'smooth'});
}
function openModal(credential){
  document.querySelector('#credential-form').reset(); document.querySelector('#json-feedback').textContent=''; document.querySelector('#json-feedback').className='json-feedback';
  document.querySelector('#credential-id').value=credential?.id||'';
  document.querySelector('#modal-title').textContent=credential?'Editar credencial':'Nova credencial';
  if(credential){document.querySelector('#credential-name').value=credential.name;document.querySelector('#credential-provider').value=credential.provider;document.querySelector('#credential-json').value=credential.json;}
  document.querySelector('#credential-modal').showModal();
}
async function editCredential(id){
  try{const item=await api(`/credentials/${id}`);openModal({...item,json:JSON.stringify(item.credential,null,2)})}catch(error){toast(error.message)}
}
async function deleteCredential(id){
  const item=state.credentials.find(c=>c.id===id); if(!item||!confirm(`Remover a integração “${item.name}”?`))return;
  try{await api(`/credentials/${id}`,{method:'DELETE'});await loadCredentials();await loadAudit();toast('Integração removida.')}catch(error){toast(error.message)}
}
async function scanCredential(id,button){
  if(button?.disabled)return;
  if(button){button.disabled=true;button.textContent='Analisando…'}
  toast('Análise em andamento. Aguarde a coleta do provedor.',300000);
  try{
    const result=await api(`/credentials/${id}/scan`,{method:'POST'});
    await Promise.all([loadCredentials(),loadAudit(),loadPlatformData()]);
    toast(`Análise concluída: ${result.findings} riscos encontrados.`);
  }catch(error){toast(error.message)}finally{if(button?.isConnected){button.disabled=false;button.textContent='Analisar'}}
}
async function resolveFinding(id){
  const justification=prompt('Informe a justificativa para resolver este risco:');
  if(!justification)return;
  try{await api(`/findings/${id}`,{method:'PATCH',body:JSON.stringify({status:'resolved',justification})});await Promise.all([loadPlatformData(),loadAudit()]);toast('Risco resolvido e auditado.')}catch(error){toast(error.message)}
}
let toastTimer;
function toast(msg,duration=2400){const el=document.querySelector('#toast');clearTimeout(toastTimer);el.textContent=msg;el.classList.add('show');toastTimer=setTimeout(()=>el.classList.remove('show'),duration)}
function escapeHtml(v){return String(v).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}

document.querySelector('#main-nav').addEventListener('click',e=>{const b=e.target.closest('[data-page]');if(b)navigate(b.dataset.page)});
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.go)));
['#new-credential-top','#new-credential-card','#new-credential-page'].forEach(s=>document.querySelector(s).addEventListener('click',()=>openModal()));
['#close-modal','#cancel-modal'].forEach(s=>document.querySelector(s).addEventListener('click',()=>document.querySelector('#credential-modal').close()));
document.querySelector('#credential-search').addEventListener('input',e=>renderCredentials(e.target.value));
document.querySelectorAll('[data-audit]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-audit]').forEach(x=>x.classList.remove('active'));b.classList.add('active');renderAudit(b.dataset.audit)}));
document.querySelector('#credential-json').addEventListener('input',e=>{const f=document.querySelector('#json-feedback');try{JSON.parse(e.target.value);f.textContent='✓ JSON válido';f.className='json-feedback ok'}catch{f.textContent=e.target.value?'JSON ainda não é válido.':'';f.className='json-feedback error'}});
document.querySelector('#credential-form').addEventListener('submit',async e=>{
  e.preventDefault();let parsed;const feedback=document.querySelector('#json-feedback');try{parsed=JSON.parse(document.querySelector('#credential-json').value)}catch{feedback.textContent='Revise a sintaxe: a credencial precisa ser um JSON válido.';feedback.className='json-feedback error';return}
  if(!parsed||Array.isArray(parsed)||typeof parsed!=='object'){feedback.textContent='A credencial precisa ser um objeto JSON.';feedback.className='json-feedback error';return}
  const id=Number(document.querySelector('#credential-id').value);const provider=document.querySelector('#credential-provider').value;const name=document.querySelector('#credential-name').value.trim();
  try{
    await api(id?`/credentials/${id}`:'/credentials',{method:id?'PUT':'POST',body:JSON.stringify({name,provider,credential:parsed})});
    await loadCredentials();await loadAudit();document.querySelector('#credential-modal').close();toast(id?'Credencial atualizada; execute uma nova análise.':'Credencial salva; execute a análise para validar a conexão.');
  }catch(error){feedback.textContent=error.message;feedback.className='json-feedback error'}
});
document.querySelector('#export-audit').addEventListener('click',()=>{
  const csv='Data,Evento,Descrição,Ator\n'+state.audit.map(e=>[e.date,e.title,e.text,e.actor].map(v=>`"${v.replaceAll('"','""')}"`).join(',')).join('\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));a.download='auditoria-nexo-iga.csv';a.click();URL.revokeObjectURL(a.href);toast('Auditoria exportada.');
});
document.querySelector('#environment-filter').addEventListener('change',async e=>{await loadDashboard(e.target.value);toast(e.target.value==='all'?'Visão consolidada aplicada.':'Ambiente selecionado.')});
document.querySelector('#global-search').addEventListener('keydown',async e=>{if(e.key==='Enter'&&e.target.value.trim()){navigate('identidades');await loadIdentities(e.target.value.trim())}});
document.querySelector('#login-form').addEventListener('submit',async e=>{
  e.preventDefault();const feedback=document.querySelector('#login-feedback');feedback.textContent='';
  try{
    const session=await api('/auth/login',{method:'POST',body:JSON.stringify({email:document.querySelector('#login-email').value,password:document.querySelector('#login-password').value})});
    state.token=session.token;state.user=session.user;localStorage.setItem('nexo.session',state.token);applyUser();await initializePlatform();
  }catch(error){feedback.textContent=error.message}
});
document.querySelector('#logout').addEventListener('click',()=>showLogin());
document.querySelector('#new-user').addEventListener('click',()=>{document.querySelector('#user-form').reset();document.querySelector('#user-feedback').textContent='';document.querySelector('#user-modal').showModal()});
['#close-user-modal','#cancel-user-modal'].forEach(selector=>document.querySelector(selector).addEventListener('click',()=>document.querySelector('#user-modal').close()));
document.querySelector('#close-privilege-modal').addEventListener('click',()=>document.querySelector('#privilege-modal').close());
document.querySelector('#close-identity-modal').addEventListener('click',()=>document.querySelector('#identity-modal').close());
document.querySelector('#close-project-modal').addEventListener('click',()=>document.querySelector('#project-modal').close());
document.querySelector('#user-form').addEventListener('submit',async e=>{
  e.preventDefault();const feedback=document.querySelector('#user-feedback');
  const payload={name:document.querySelector('#new-user-name').value,email:document.querySelector('#new-user-email').value,password:document.querySelector('#new-user-password').value,role:document.querySelector('#new-user-role').value};
  try{await api('/users',{method:'POST',body:JSON.stringify(payload)});document.querySelector('#user-modal').close();await loadUsers();toast('Usuário criado com sucesso.')}catch(error){feedback.textContent=error.message}
});

async function loadCredentials(){
  try{state.credentials=await api('/credentials');renderCredentials(document.querySelector('#credential-search').value)}catch(error){toast(`API indisponível: ${error.message}`)}
}
async function loadAudit(){
  try{
    const remote=await api('/audit');
    const normalized=remote.map(e=>({...e,date:new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short'}).format(new Date(e.createdAt))}));
    state.audit=[...normalized,...state.audit.filter(e=>!e.createdAt)];renderAudit(document.querySelector('[data-audit].active')?.dataset.audit||'all');
  }catch(error){toast(`Auditoria indisponível: ${error.message}`)}
}

async function loadPlatformData(){
  try{
    const [identities,accesses,findings,privileged,ueba,uebaStatus,compliance,resources,rules,aiAnalyses,projects,roles,accounts]=await Promise.all([api('/identities?limit=10000'),api('/accesses?limit=20000'),api('/findings?limit=20000'),api('/privileged-access?limit=20000'),api('/ueba?limit=20000'),api('/ueba/status'),api('/compliance'),api('/resources?limit=20000'),api('/rules'),api('/ai-analyses?limit=100'),api('/inventory/projects?limit=10000'),api('/inventory/roles?limit=10000'),api('/inventory/accounts?limit=10000')]);
    const labels={critical:'Crítico',high:'Alto',medium:'Médio',low:'Baixo'};
    state.risks=findings.slice(0,8).map(item=>({id:item.id,title:item.title,meta:`${item.rule} · ${item.identityId||item.resourceId||'Ambiente'}`,level:labels[item.severity]||item.severity,type:item.severity}));
    renderRisks();
    const ruleStatus={failed:'Violação',passed:'Avaliado sem achados',not_assessed:'Dados insuficientes'};
    renderIdentities(identities);
    appendInventoryTable('projetos','Projetos e recursos com concessões reais',projects.map(item=>[
      {html:`<div class="identity-main"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.resourceId)}</small></div>`},
      `${item.provider} · ${item.environment}`,item.type,String(item.identityCount),String(item.accessCount),String(item.privilegedCount),
      {html:item.findingCount?`<span class="badge ${escapeHtml(item.maxSeverity||'medium')}">${item.findingCount} · ${escapeHtml((item.maxSeverity||'medium').toUpperCase())}</span>`:'Nenhum'},
      {html:`<button class="detail-btn" onclick="openProjectDetail(${Number(item.credentialId)},'${encodeURIComponent(item.resourceId)}')">Abrir projeto</button>`}
    ]),['Projeto / recurso','Ambiente','Tipo','Identidades','Concessões','Privilegiados','Riscos','Drill down'],'projects');
    appendInventoryTable('roles','Roles concedidas nos ambientes',roles.map(item=>[
      {html:`<div class="identity-main"><strong>${escapeHtml(item.roleLabel)}</strong><small>${escapeHtml(item.role)}</small></div>`},
      `${item.provider} · ${item.environment}`,item.capability,String(item.identityCount),String(item.resourceCount),String(item.accessCount),String(item.privilegedCount),
      {html:`<span class="badge ${escapeHtml(item.severity)}">${escapeHtml(item.severity.toUpperCase())}</span>`},String(item.findingCount)
    ]),['Role','Ambiente','Capacidade efetiva','Identidades','Projetos / recursos','Concessões','Privilegiados','Criticidade','Riscos correlacionados'],'roles');
    appendInventoryTable('contas','Contas humanas e não humanas',accounts.map(item=>[
      {html:`<div class="identity-main"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.externalId)}</small></div>`},
      `${item.provider} · ${item.environment}`,item.type,item.enabled?'Ativa':'Desabilitada',String(item.resourceCount),String(item.accessCount),String(item.privilegedCount),String(item.findingCount),
      {html:`<button class="detail-btn" onclick="openIdentityDetail(${Number(item.id)})">Ver conta</button>`}
    ]),['Conta','Ambiente','Tipo','Estado','Projetos / recursos','Concessões','Privilegiados','Riscos','Detalhes'],'accounts');
    appendInventoryTable('acessos','Todas as concessões analisadas',accesses.map(item=>[item.identityId,item.resourceName,item.role,item.privileged?'Privilegiado':'Padrão',item.lastUsedAt||'Telemetria indisponível']),['Identidade','Recurso','Função','Nível','Último uso'],'grants');
    appendInventoryTable('riscos','Cobertura das regras e frameworks',rules.map(item=>[item.name,item.framework,item.control,ruleStatus[item.status],String(item.findings)]),['Regra','Framework','Controle','Avaliação','Achados'],'rules');
    appendInventoryTable('riscos','Análises persistidas do Qwen',aiAnalyses.filter(item=>item.scopeType==='platform').map(item=>[formatDate(item.createdAt),item.engine,item.priority.toUpperCase(),item.summary,item.recommendation,item.treatment]),['Data','Motor','Prioridade','Análise','Recomendação','Tratativa'],'ai');
    appendInventoryTable('riscos','Todos os achados ativos',findings.map(item=>[item.severity.toUpperCase(),item.title,item.why,item.recommendation,item.treatment,item.identityId||'—']),['Criticidade','Achado','Por quê','Recomendação','Tratativa','Identidade'],'findings');
    appendInventoryTable('privilegiados','Todos os acessos privilegiados ativos',privileged.map(item=>[
      item.identityName,item.environment,`${item.resourceType}: ${item.resourceName}`,item.roleLabel,item.capability,item.severity.toUpperCase(),
      {html:`<button class="detail-btn" onclick="openPrivilegeDetail(${Number(item.id)})">Ver contexto</button>`}
    ]),['Identidade','Credencial','Escopo','Função interpretada','Capacidade','Criticidade','Detalhes'],'privileged');
    appendInventoryTable('ueba',`Cobertura de telemetria · ${uebaStatus.eventsEvaluated} eventos avaliados`,uebaStatus.environments.map(item=>[
      `${item.provider} · ${item.environment}`,item.status,item.message,String(item.eventsEvaluated),String(item.anomalies),item.finishedAt?formatDate(item.finishedAt):'Nunca'
    ]),['Ambiente','Estado','Diagnóstico','Eventos avaliados','Anomalias','Última análise'],'coverage');
    appendInventoryTable('ueba','Anomalias comportamentais confirmadas',ueba.map(item=>[item.severity.toUpperCase(),item.identityId||'—',item.resourceId||'—',item.description,formatDate(item.createdAt)]),['Severidade','Identidade','Recurso','Comportamento','Detectado em'],'ueba');
    appendInventoryTable('compliance',`Controles de conformidade · ${compliance.score}%`,compliance.controls.map(item=>[item.code,item.name,`${item.score}%`,item.status==='compliant'?'Conforme':item.status==='non_compliant'?'Não conforme':'Não avaliado']),['Controle','Descrição','Cobertura','Situação'],'compliance');
    appendInventoryTable('acessos','Todos os projetos e recursos descobertos',resources.map(item=>[item.name,item.externalId,item.type,String(item.credentialId)]),['Ambiente','Identificador','Tipo','Integração'],'resources');
    await loadDashboard();
  }catch(error){toast(`Inventários indisponíveis: ${error.message}`)}
}
function renderIdentities(identities,query=''){
  appendInventoryTable('identidades','Identidades correlacionadas',identities.map(item=>[
    {html:`<div class="identity-main"><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.externalId)}</small></div>`},
    `${item.provider} · ${item.environment}`,item.type,String(item.resourceCount),String(item.accessCount),String(item.privilegedCount),
    {html:item.findingCount?`<span class="badge ${escapeHtml(item.maxSeverity||'medium')}">${item.findingCount} · ${escapeHtml((item.maxSeverity||'medium').toUpperCase())}</span>`:'Nenhum'},
    {html:`<button class="detail-btn" onclick="openIdentityDetail(${Number(item.id)})">Ver identidade</button>`}
  ]),['Identidade','Ambiente','Tipo','Projetos / recursos','Concessões','Privilegiados','Riscos','Detalhes'],'identities');
  const panel=document.querySelector('#identidades .inventory-live[data-panel="identities"]');
  panel.querySelector('.table-tools').innerHTML=`<div class="table-search"><input id="identity-search" value="${escapeHtml(query)}" placeholder="Buscar nome, e-mail ou ID"><button class="detail-btn" id="identity-search-btn">Buscar</button></div><span>${identities.length} identidades exibidas</span>`;
  const search=()=>loadIdentities(document.querySelector('#identity-search').value);
  document.querySelector('#identity-search-btn').addEventListener('click',search);
  document.querySelector('#identity-search').addEventListener('keydown',event=>{if(event.key==='Enter')search()});
}
async function loadIdentities(query=''){
  try{renderIdentities(await api(`/identities?limit=10000${query?`&q=${encodeURIComponent(query)}`:''}`),query)}catch(error){toast(`Não foi possível consultar identidades: ${error.message}`)}
}
function appendInventoryTable(pageId,title,rows,headers,key='default'){
  const page=document.querySelector(`#${pageId}`);let panel=page.querySelector(`.inventory-live[data-panel="${key}"]`);
  if(!panel){panel=document.createElement('div');panel.className='table-panel inventory-live';panel.dataset.panel=key;page.appendChild(panel)}
  panel.innerHTML=`<div class="table-tools"><strong>${title}</strong><span>${rows.length} registros</span></div><div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${escapeHtml(h)}</th>`).join('')}</tr></thead><tbody>${rows.length?rows.map(row=>`<tr>${row.map(cell=>`<td>${cell&&typeof cell==='object'&&cell.html?cell.html:escapeHtml(cell)}</td>`).join('')}</tr>`).join(''):`<tr><td colspan="${headers.length}">Execute uma análise para preencher este inventário.</td></tr>`}</tbody></table></div>`;
}

async function openPrivilegeDetail(id){
  const modal=document.querySelector('#privilege-modal');const content=document.querySelector('#privilege-content');
  content.innerHTML='<div class="analysis-loading">Carregando contexto e análise local Qwen…</div>';modal.showModal();
  try{
    const result=await api(`/privileged-access/${id}/analysis`,{method:'POST'});const d=result.dossier,a=result.analysis;
    const path=d.accessPath.map(item=>`<tr><td>${escapeHtml(item.resource_name)}</td><td>${escapeHtml(item.resource_id)}</td><td>${escapeHtml(item.role_name)}</td><td>${item.privileged?'Sim':'Não'}</td></tr>`).join('');
    const findings=d.relatedFindings.map(item=>`<li><strong>${escapeHtml(item.severity.toUpperCase())} · ${escapeHtml(item.title)}</strong><span>${escapeHtml(item.description)}</span></li>`).join('')||'<li>Nenhum achado correlacionado.</li>';
    content.innerHTML=`<div class="dossier-grid"><div><span>Identidade</span><strong>${escapeHtml(d.identityName)}</strong><small>${escapeHtml(d.identityType||'—')} · ${escapeHtml(d.identityId)}</small></div><div><span>Credencial</span><strong>${escapeHtml(d.credential)}</strong><small>${escapeHtml(d.provider)}</small></div><div><span>Projeto / recurso</span><strong>${escapeHtml(d.project)}</strong><small>${escapeHtml(d.resourceType)} · ${escapeHtml(d.resourceId)}</small></div><div><span>Repositório</span><strong>${escapeHtml(d.repository||'Não identificado nesta política')}</strong><small>${d.repository?'Escopo comprovado':'A função está no escopo de projeto; nenhum repositório foi inventado.'}</small></div><div><span>Função</span><strong>${escapeHtml(d.roleLabel)}</strong><small>${escapeHtml(d.role)}</small></div><div><span>Criticidade</span><strong class="badge ${escapeHtml(d.severity)}">${escapeHtml(d.severity.toUpperCase())}</strong><small>${escapeHtml(d.capability)}</small></div></div><section class="ai-analysis"><p class="eyebrow">ANÁLISE LOCAL · ${escapeHtml(result.engine)}</p><h3>${escapeHtml(a.summary||d.capability)}</h3><dl><dt>Por quê</dt><dd>${escapeHtml(a.why)}</dd><dt>Recomendação</dt><dd>${escapeHtml(a.recommendation)}</dd><dt>Tratativa</dt><dd>${escapeHtml(a.treatment)}</dd></dl></section><section><h3>Riscos correlacionados</h3><ul class="finding-list">${findings}</ul></section><section><h3>Caminho de acesso da identidade</h3><div class="table-wrap"><table><thead><tr><th>Recurso</th><th>ID</th><th>Função</th><th>Privilegiado</th></tr></thead><tbody>${path}</tbody></table></div></section>`;
  }catch(error){content.innerHTML=`<div class="json-feedback error">${escapeHtml(error.message)}</div>`}
}

async function openIdentityDetail(id){
  const modal=document.querySelector('#identity-modal');const content=document.querySelector('#identity-content');
  content.innerHTML='<div class="analysis-loading">Carregando identidade, concessões e riscos correlacionados…</div>';modal.showModal();
  try{
    const d=await api(`/identities/${id}`);
    const accesses=d.accesses.map(item=>`<tr><td>${escapeHtml(item.resourceName)}</td><td>${escapeHtml(item.resourceType)}</td><td><strong>${escapeHtml(item.roleLabel)}</strong><br><small>${escapeHtml(item.role)}</small></td><td>${item.privileged?'Sim':'Não'}</td><td>${escapeHtml(item.capability)}</td></tr>`).join('')||'<tr><td colspan="5">Nenhuma concessão coletada para esta identidade.</td></tr>';
    const findings=d.findings.map(item=>`<li><strong>${escapeHtml(item.severity.toUpperCase())} · ${escapeHtml(item.title)}</strong><span>${escapeHtml(item.description)}</span><small><b>Tratativa:</b> ${escapeHtml(item.treatment)}</small></li>`).join('')||'<li>Nenhum risco ativo correlacionado.</li>';
    const mfa=d.mfaEnabled===true?'Verificado':d.mfaEnabled===false?'Ausente':'Não fornecido pelo provedor';
    content.innerHTML=`<div class="dossier-grid"><div><span>Identidade</span><strong>${escapeHtml(d.name)}</strong><small>${escapeHtml(d.externalId)}</small></div><div><span>Ambiente</span><strong>${escapeHtml(d.environment)}</strong><small>${escapeHtml(d.provider)}</small></div><div><span>Tipo</span><strong>${escapeHtml(d.type)}</strong><small>${d.enabled?'Ativa':'Desabilitada'}</small></div><div><span>E-mail</span><strong>${escapeHtml(d.email||'Não fornecido pelo provedor')}</strong><small>Responsável: ${escapeHtml(d.owner||'não fornecido')}</small></div><div><span>Postura de autenticação</span><strong>${escapeHtml(mfa)}</strong><small>Ciclo de vida: ${escapeHtml(d.lifecycleStatus||'não fornecido')}</small></div><div><span>Escopo correlacionado</span><strong>${d.resourceCount} projetos/recursos</strong><small>${d.accesses.length} concessões · ${d.privilegedCount} privilegiadas</small></div></div><section><h3>Riscos correlacionados (${d.findings.length})</h3><ul class="finding-list">${findings}</ul></section><section><h3>Caminho de acesso (${d.accesses.length})</h3><div class="table-wrap"><table><thead><tr><th>Projeto / recurso</th><th>Tipo</th><th>Função</th><th>Privilegiado</th><th>Capacidade efetiva</th></tr></thead><tbody>${accesses}</tbody></table></div></section>`;
  }catch(error){content.innerHTML=`<div class="json-feedback error">${escapeHtml(error.message)}</div>`}
}

let activeProjectDossier=null;
async function openProjectDetail(credentialId,encodedResourceId){
  const modal=document.querySelector('#project-modal');const content=document.querySelector('#project-content');
  content.innerHTML='<div class="analysis-loading">Carregando roles e contas do projeto…</div>';modal.showModal();
  try{
    activeProjectDossier=await api(`/inventory/project-detail?credential_id=${credentialId}&resource_id=${encodeURIComponent(decodeURIComponent(encodedResourceId))}`);
    renderProjectRoles();
  }catch(error){content.innerHTML=`<div class="json-feedback error">${escapeHtml(error.message)}</div>`}
}
function renderProjectRoles(){
  const d=activeProjectDossier;if(!d)return;
  const rows=d.roles.map((role,index)=>`<tr><td><strong>${escapeHtml(role.roleLabel)}</strong><br><small>${escapeHtml(role.role)}</small></td><td>${escapeHtml(role.capability)}</td><td>${role.accounts.length}</td><td>${role.privileged?'Sim':'Não'}</td><td><span class="badge ${escapeHtml(role.severity)}">${escapeHtml(role.severity.toUpperCase())}</span></td><td><button class="detail-btn" onclick="openProjectRole(${index})">Abrir contas</button></td></tr>`).join('')||'<tr><td colspan="6">Nenhuma role encontrada.</td></tr>';
  document.querySelector('#project-content').innerHTML=`<div class="drill-path"><strong>${escapeHtml(d.name)}</strong><span>›</span><span>Roles</span></div><div class="dossier-grid"><div><span>Ambiente</span><strong>${escapeHtml(d.environment)}</strong><small>${escapeHtml(d.provider)}</small></div><div><span>Projeto / recurso</span><strong>${escapeHtml(d.name)}</strong><small>${escapeHtml(d.resourceId)}</small></div><div><span>Alcance</span><strong>${d.roleCount} roles · ${d.accountCount} contas</strong><small>${d.accessCount} concessões</small></div></div><div class="table-wrap"><table><thead><tr><th>Role</th><th>Capacidade efetiva</th><th>Contas</th><th>Privilegiada</th><th>Criticidade</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function openProjectRole(index){
  const d=activeProjectDossier;const role=d?.roles[index];if(!role)return;
  const rows=role.accounts.map(account=>`<tr><td><strong>${escapeHtml(account.name)}</strong><br><small>${escapeHtml(account.externalId)}</small></td><td>${escapeHtml(account.type)}</td><td>${escapeHtml(account.email||'Não fornecido')}</td><td>${account.privileged?'Sim':'Não'}</td><td>${account.id?`<button class="detail-btn" onclick="openAccountFromProject(${Number(account.id)})">Abrir conta</button>`:'Conta sem cadastro normalizado'}</td></tr>`).join('')||'<tr><td colspan="5">Nenhuma conta vinculada.</td></tr>';
  document.querySelector('#project-content').innerHTML=`<div class="drill-path"><button onclick="renderProjectRoles()">${escapeHtml(d.name)}</button><span>›</span><strong>${escapeHtml(role.roleLabel)}</strong><span>›</span><span>Contas</span></div><section class="ai-analysis"><p class="eyebrow">CAPACIDADE EFETIVA</p><h3>${escapeHtml(role.roleLabel)}</h3><p>${escapeHtml(role.capability)}</p><small>${escapeHtml(role.role)}</small></section><div class="table-wrap"><table><thead><tr><th>Conta</th><th>Tipo</th><th>E-mail</th><th>Privilegiada</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function openAccountFromProject(identityId){
  document.querySelector('#project-modal').close();openIdentityDetail(identityId);
}

async function loadDashboard(selection='all'){
  const query=selection==='all'?'':`?credential_id=${encodeURIComponent(selection)}`;
  const [dashboard,history]=await Promise.all([api(`/dashboard${query}`),api(`/risk-history${query}`)]);
  const picker=document.querySelector('#environment-filter');
  const current=selection||picker.value||'all';
  picker.innerHTML='<option value="all">Todos os domínios e ambientes</option>'+dashboard.credentials.map(item=>`<option value="${item.id}">${escapeHtml(item.name)} · ${item.provider}</option>`).join('');
  picker.value=current;
  document.querySelector('#risk-score').textContent=dashboard.riskScore;
  const ring=document.querySelector('.score-ring');
  ring.classList.remove('score-low','score-moderate','score-high','score-critical','score-68','score-empty');
  ring.classList.add(dashboard.assessedEnvironments?`score-${dashboard.riskLevel}`:'score-empty');
  document.querySelector('#metric-identities').textContent=dashboard.identities.toLocaleString('pt-BR');
  document.querySelector('#metric-accesses').textContent=dashboard.accesses.toLocaleString('pt-BR');
  document.querySelector('#metric-privileged').textContent=dashboard.privilegedAccesses.toLocaleString('pt-BR');
  document.querySelector('#metric-compliance').textContent=dashboard.compliance===null?'N/A':`${dashboard.compliance}%`;
  const total=Object.values(dashboard.severities).reduce((sum,value)=>sum+value,0);
  document.querySelector('#active-risk-count').textContent=total;
  document.querySelector('#environment-count').textContent=`em ${dashboard.assessedEnvironments} ambiente(s) analisado(s)`;
  document.querySelector('#monitoring-status').textContent=dashboard.assessedEnvironments?'Monitoramento com dados reais':dashboard.credentials.length?'Credencial aguardando análise':'Monitoramento não iniciado';
  document.querySelector('#last-analysis').textContent=history.length?`Última análise em ${new Intl.DateTimeFormat('pt-BR',{dateStyle:'short',timeStyle:'short'}).format(new Date(history.at(-1).finishedAt))}`:'Nenhuma análise executada';
  document.querySelector('.status-dot').classList.toggle('idle',!dashboard.credentials.length);
  const riskLabel=document.querySelector('#risk-label');
  const riskSummary=document.querySelector('#risk-summary');
  const riskTrend=document.querySelector('#risk-trend');
  if(!dashboard.assessedEnvironments){riskLabel.textContent='SEM DADOS';riskSummary.textContent=dashboard.credentials.length?'Execute a primeira análise para validar a credencial e coletar dados reais.':'Nenhuma credencial cadastrada. Adicione uma credencial para iniciar a análise.';riskTrend.textContent='Sem dados'}
  else if(total===0){riskLabel.textContent='SEM RISCOS ATIVOS';riskSummary.textContent='Nenhum risco foi identificado nos ambientes analisados.';riskTrend.textContent='Ambiente sem riscos'}
  else{const levelNames={critical:'RISCO CRÍTICO',high:'RISCO ALTO',moderate:'RISCO MODERADO',low:'RISCO BAIXO'};riskLabel.textContent=levelNames[dashboard.riskLevel]||'RISCO';riskSummary.textContent=`${total} risco(s) ativo(s), incluindo ${dashboard.severities.critical||0} crítico(s), exigem avaliação.`;riskTrend.textContent='Dados da última análise'}
  const maximum=Math.max(1,...Object.values(dashboard.severities));
  for(const level of ['critical','high','medium','low']){
    const count=dashboard.severities[level]||0;
    document.querySelector(`#count-${level}`).textContent=count;
    const bar=document.querySelector(`#bar-${level}`);
    bar.className=`${level} width-${Math.ceil((count/maximum)*4)*25}`;
  }
  renderRiskHistory(history);
}

function renderRiskHistory(history){
  const chart=document.querySelector('#risk-history-chart');
  const caption=document.querySelector('#history-caption');
  if(!history.length){chart.innerHTML='<div class="chart-empty">Execute uma análise para iniciar o histórico.</div>';caption.textContent='Aguardando análises';return}
  const width=900,height=150,left=36,right=18,top=12,bottom=25;
  const usableWidth=width-left-right,usableHeight=height-top-bottom;
  const points=history.map((item,index)=>{
    const x=history.length===1?left+usableWidth/2:left+(index/(history.length-1))*usableWidth;
    const y=top+((100-item.riskScore)/100)*usableHeight;
    return {...item,x,y};
  });
  const line=points.map(point=>`${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(' ');
  const area=`${left},${height-bottom} ${line} ${points.at(-1).x},${height-bottom}`;
  const grid=[0,50,100].map(value=>{const y=top+((100-value)/100)*usableHeight;return `<line class="chart-grid" x1="${left}" y1="${y}" x2="${width-right}" y2="${y}"/><text class="chart-label" x="3" y="${y+3}">${value}</text>`}).join('');
  const dots=points.map(point=>`<circle class="chart-point" cx="${point.x}" cy="${point.y}" r="4"><title>${escapeHtml(point.environment)} · ${point.riskScore}/100 · ${point.findings} riscos</title></circle>`).join('');
  const firstDate=new Intl.DateTimeFormat('pt-BR',{day:'2-digit',month:'short'}).format(new Date(points[0].finishedAt));
  const lastDate=new Intl.DateTimeFormat('pt-BR',{day:'2-digit',month:'short'}).format(new Date(points.at(-1).finishedAt));
  chart.innerHTML=`<svg viewBox="0 0 ${width} ${height}" role="img"><title>Evolução da nota de postura</title>${grid}<polygon class="chart-area" points="${area}"/><polyline class="chart-line" points="${line}"/>${dots}<text class="chart-label" x="${left}" y="${height-3}">${firstDate}</text><text class="chart-label" text-anchor="end" x="${width-right}" y="${height-3}">${lastDate}</text></svg>`;
  const delta=points.at(-1).riskScore-points[0].riskScore;
  caption.textContent=history.length===1?'Primeira medição':`${delta>=0?'+':''}${delta} pontos no período`;
  caption.className=`trend ${delta>=0?'good':'badge critical'}`;
}

function showLogin(){
  state.token='';state.user=null;localStorage.removeItem('nexo.session');document.body.classList.add('locked');document.querySelector('#login-screen').classList.remove('authenticated');document.querySelector('#login-password').value='';
}
function applyUser(){
  document.body.classList.remove('locked');document.querySelector('#login-screen').classList.add('authenticated');
  document.querySelector('#user-name').textContent=state.user.name;
  const roleLabels={admin:'Administrador',analyst:'Analista',auditor:'Auditor'};
  document.querySelector('#user-role').textContent=roleLabels[state.user.role]||state.user.role;
  document.querySelector('#user-avatar').textContent=state.user.name.split(/\s+/).map(part=>part[0]).join('').slice(0,2).toUpperCase();
  document.querySelectorAll('.admin-only').forEach(element=>element.classList.toggle('hidden',state.user.role!=='admin'));
  ['#new-credential-top','#new-credential-card','#new-credential-page'].forEach(selector=>document.querySelector(selector).hidden=state.user.role==='auditor');
}
async function loadUsers(){
  if(state.user?.role!=='admin')return;
  const users=await api('/users');document.querySelector('#user-count').textContent=`${users.length} usuários`;
  document.querySelector('#users-body').innerHTML=users.map(user=>`<tr><td><strong>${escapeHtml(user.name)}</strong></td><td>${escapeHtml(user.email)}</td><td><span class="badge medium">${escapeHtml(user.role)}</span></td><td>${user.active?'<span class="status-pill">● Ativo</span>':'Inativo'}</td><td class="row-actions">${user.id===state.user.id?'Sessão atual':`<button onclick="togglePlatformUser(${user.id},${user.active})">${user.active?'Desativar':'Ativar'}</button><button class="delete" onclick="deletePlatformUser(${user.id})">Remover</button>`}</td></tr>`).join('');
}
async function togglePlatformUser(id,active){try{await api(`/users/${id}`,{method:'PATCH',body:JSON.stringify({active:!active})});await loadUsers();toast('Acesso do usuário atualizado.')}catch(error){toast(error.message)}}
async function deletePlatformUser(id){if(!confirm('Remover este usuário da plataforma?'))return;try{await api(`/users/${id}`,{method:'DELETE'});await loadUsers();toast('Usuário removido.')}catch(error){toast(error.message)}}
async function initializePlatform(){
  renderRisks();renderCredentials();renderAudit();renderModules();
  await Promise.all([loadCredentials(),loadAudit(),loadPlatformData(),loadUsers()]);
}
async function bootstrap(){
  if(!state.token){showLogin();return}
  try{state.user=await api('/auth/me');applyUser();await initializePlatform()}catch{showLogin()}
}

bootstrap();
