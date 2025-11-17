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
  const tbody = document.querySelector('#rulesTable tbody')
  tbody.innerHTML = ''
  let allow=0, deny=0
  j.rules.forEach(r => {
    const tr = document.createElement('tr')
    tr.innerHTML = `
      <td>${r.id||''}</td>
      <td>${r.priority||''}</td>
      <td>${r.action||''}</td>
      <td>${r.src_ip||'*'}</td>
      <td>${r.dst_ip||'*'}</td>
      <td>${r.port||'*'}</td>
      <td>${r.protocol||'*'}</td>
      <td></td>
    `
    const ops = tr.querySelector('td:last-child')
    const edit = document.createElement('button')
    edit.textContent = 'Edit'
    edit.className = 'ghost'
    edit.addEventListener('click', () => openEditModal(r))
    const del = document.createElement('button')
    del.textContent = 'Delete'
    del.style.marginLeft = '8px'
    del.addEventListener('click', () => deleteRule(r.id))
    ops.appendChild(edit)
    ops.appendChild(del)
    tbody.appendChild(tr)
  })
  document.getElementById('allowCount').textContent = allow
  document.getElementById('denyCount').textContent = deny
}

// Modal editing
let _editingId = null
function openEditModal(r){
  _editingId = r.id
  document.getElementById('m_action').value = r.action || 'allow'
  document.getElementById('m_src').value = r.src_ip || ''
  document.getElementById('m_dst').value = r.dst_ip || ''
  document.getElementById('m_port').value = r.port || ''
  document.getElementById('m_proto').value = r.protocol || ''
  document.getElementById('m_prio').value = r.priority || 100
  document.getElementById('editModal').classList.add('show')
}

function closeEditModal(){
  _editingId = null
  document.getElementById('editModal').classList.remove('show')
}

document.getElementById('m_cancel').addEventListener('click', ()=> closeEditModal())
document.getElementById('m_save').addEventListener('click', async ()=>{
  if(!_editingId) return closeEditModal()
  const payload = {
    action: document.getElementById('m_action').value,
    src_ip: document.getElementById('m_src').value || undefined,
    dst_ip: document.getElementById('m_dst').value || undefined,
    port: document.getElementById('m_port').value ? parseInt(document.getElementById('m_port').value) : undefined,
    protocol: document.getElementById('m_proto').value || undefined,
    priority: document.getElementById('m_prio').value ? parseInt(document.getElementById('m_prio').value) : undefined
  }
  await fetch(`${apiBase}/rules/${_editingId}`, { method: 'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) })
  closeEditModal()
  await refreshRules()
})

// search/filter
// search/filter (works on table rows)
document.getElementById('ruleSearch').addEventListener('input', (e)=>{
  const q = e.target.value.toLowerCase()
  document.querySelectorAll('#rulesTable tbody tr').forEach(tr=>{
    tr.style.display = tr.textContent.toLowerCase().includes(q)?'table-row':'none'
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
