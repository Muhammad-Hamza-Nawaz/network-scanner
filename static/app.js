const apiBase = '/api'

async function startScan(){
  const target = document.getElementById('target').value
  const scanType = document.getElementById('scanType').value
  const ports = document.getElementById('ports').value
  const body = { target, scan_type: scanType, ports }
  setResults([])
  const res = await fetch(`${apiBase}/scan`, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body)})
  const j = await res.json()
  setResults(j.results || [])
}

function setResults(rows){
  const tbody = document.querySelector('#resultsTable tbody')
  tbody.innerHTML = ''
  rows.forEach(r => {
    const tr = document.createElement('tr')
    tr.innerHTML = `<td>${r.ip}</td><td>${r.port}</td><td>${r.service || ''}</td><td>${r.status}</td>`
    tbody.appendChild(tr)
  })
}

async function addRule(e){
  e.preventDefault()
  const payload = {
    action: document.getElementById('action').value,
    src_ip: document.getElementById('src').value || undefined,
    dst_ip: document.getElementById('dst').value || undefined,
    port: parseInt(document.getElementById('rport').value) || undefined,
    protocol: document.getElementById('proto').value || undefined,
    priority: parseInt(document.getElementById('priority').value) || 100
  }
  await fetch(`${apiBase}/rules`, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  await refreshRules()
}

async function refreshRules(){
  const res = await fetch(`${apiBase}/rules`)
  const j = await res.json()
  const ul = document.getElementById('rulesList')
  ul.innerHTML = ''
  let allow=0, deny=0
  j.rules.forEach(r => {
    const li = document.createElement('li')
    const txt = document.createElement('span')
    txt.textContent = `${r.priority}: ${r.action.toUpperCase()} src=${r.src_ip||'*'} dst=${r.dst_ip||'*'} port=${r.port||'*'} proto=${r.protocol||'*'}`
    li.appendChild(txt)
    const edit = document.createElement('button')
    edit.textContent = 'Edit'
    edit.style.marginLeft = '8px'
    edit.addEventListener('click', () => startEdit(li, r))
    li.appendChild(edit)
    const del = document.createElement('button')
    del.textContent = 'Delete'
    del.style.marginLeft = '8px'
    del.addEventListener('click', () => deleteRule(r.id))
    li.appendChild(del)
    ul.appendChild(li)
  })
  // update counts by evaluating a few sample packets? We'll just keep counts zero until evals
  document.getElementById('allowCount').textContent = allow
  document.getElementById('denyCount').textContent = deny
}

function startEdit(li, r){
  li.innerHTML = ''
  // create small form
  const aSel = document.createElement('select')
  ['allow','deny'].forEach(v=>{ const o=document.createElement('option'); o.value=v; o.textContent=v; if(r.action===v) o.selected=true; aSel.appendChild(o) })
  const src = document.createElement('input'); src.value = r.src_ip||''; src.placeholder='src'
  const dst = document.createElement('input'); dst.value = r.dst_ip||''; dst.placeholder='dst'
  const port = document.createElement('input'); port.value = r.port||''; port.placeholder='port'; port.style.width='60px'
  const proto = document.createElement('input'); proto.value = r.protocol||''; proto.placeholder='proto'; proto.style.width='60px'
  const pr = document.createElement('input'); pr.value = r.priority||100; pr.placeholder='priority'; pr.style.width='60px'
  const save = document.createElement('button'); save.textContent='Save'
  const cancel = document.createElement('button'); cancel.textContent='Cancel'
  li.appendChild(aSel); li.appendChild(src); li.appendChild(dst); li.appendChild(port); li.appendChild(proto); li.appendChild(pr); li.appendChild(save); li.appendChild(cancel)
  save.addEventListener('click', async ()=>{
    const payload = { action: aSel.value, src_ip: src.value||undefined, dst_ip: dst.value||undefined, port: port.value?parseInt(port.value):undefined, protocol: proto.value||undefined, priority: pr.value?parseInt(pr.value):undefined }
    await fetch(`${apiBase}/rules/${r.id}`, { method: 'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
    await refreshRules()
  })
  cancel.addEventListener('click', ()=> refreshRules())
}

// search/filter
document.getElementById('ruleSearch').addEventListener('input', (e)=>{
  const q = e.target.value.toLowerCase()
  document.querySelectorAll('#rulesList li').forEach(li=>{
    li.style.display = li.textContent.toLowerCase().includes(q)?'block':'none'
  })
})

async function deleteRule(id){
  if(!confirm('Delete rule ' + id + '?')) return
  await fetch(`${apiBase}/rules/${id}`, { method: 'DELETE' })
  await refreshRules()
}

async function evaluate(){
  const payload = {
    src_ip: document.getElementById('p_src').value,
    dst_ip: document.getElementById('p_dst').value,
    port: parseInt(document.getElementById('p_port').value),
    protocol: document.getElementById('p_proto').value
  }
  const res = await fetch(`${apiBase}/evaluate`, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  const j = await res.json()
  document.getElementById('evalResult').textContent = `Result: ${j.action.toUpperCase()}`
  // increment counters visually
  const allowEl = document.getElementById('allowCount')
  const denyEl = document.getElementById('denyCount')
  if(j.action === 'allow') allowEl.textContent = parseInt(allowEl.textContent||'0') + 1
  else denyEl.textContent = parseInt(denyEl.textContent||'0') + 1
}

document.getElementById('startScan').addEventListener('click', startScan)
document.getElementById('ruleForm').addEventListener('submit', addRule)
document.getElementById('evalPacket').addEventListener('click', evaluate)
refreshRules()

// wire new controls
document.getElementById('clearRules').addEventListener('click', async (e) => {
  e.preventDefault()
  if(!confirm('Clear all rules?')) return
  await fetch(`${apiBase}/rules/clear`, { method: 'POST' })
  await refreshRules()
})

document.getElementById('defaultAction').addEventListener('change', async (e) => {
  const action = e.target.value
  await fetch(`${apiBase}/firewall/default`, { method: 'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ default_action: action }) })
})

async function refreshFirewallDefaults(){
  try{
    const res = await fetch(`${apiBase}/firewall`)
    const j = await res.json()
    document.getElementById('defaultAction').value = j.default_action || 'allow'
  }catch(e){/* ignore */}
}

refreshFirewallDefaults()
