/* Byte2craft NixFence Community Alpha. No remote calls except same-origin read-only demo API. */
const SAMPLE_POLICY = {
  name: "web-prod-baseline",
  default_input_action: "DROP",
  management_sources: ["10.10.0.0/16"],
  rules: [
    { id: "MGMT-SSH", priority: 10, source: "10.10.0.0/16", protocol: "tcp", destination_port: 22, action: "ACCEPT", description: "Management SSH" },
    { id: "WEB-HTTPS", priority: 20, source: "10.20.0.0/16", protocol: "tcp", destination_port: 443, action: "ACCEPT", description: "Internal HTTPS" },
    { id: "DB-DENY", priority: 30, source: "0.0.0.0/0", protocol: "tcp", destination_port: 3306, action: "DROP", description: "Deny MySQL" }
  ]
};
const panelNames = {overview:"Overview",hosts:"Linux Hosts",policies:"Firewall Policies",selinux:"SELinux",playground:"Policy Playground"};
function element(tag, text, className="") {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = String(text);
  if (className) el.className = className;
  return el;
}
function navigate(name) {
  if (!panelNames[name]) return;
  document.querySelectorAll(".panel").forEach(el => el.classList.toggle("active", el.id === `panel-${name}`));
  document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.panel === name));
  document.getElementById("breadcrumb-current").textContent = panelNames[name];
  window.scrollTo({top:0,behavior:"smooth"});
}
document.querySelectorAll("[data-panel]").forEach(el => el.addEventListener("click",()=>navigate(el.dataset.panel)));
document.querySelectorAll("[data-navigate]").forEach(el => el.addEventListener("click",()=>navigate(el.dataset.navigate)));

function appendDemoHost(container, h) {
  const row=element("div",null,"host-row");
  const left=element("div",null,"host-left"); const icon=element("span","▤","host-icon");
  const info=element("div");info.append(element("strong",h.hostname),element("small",h.group+" · "+h.address));
  left.append(icon,info);row.append(left,element("span",h.selinux,h.selinux==="Enforcing"?"chip":"chip warning"));
  container.append(row);
}
function renderHosts(hosts) {
  const preview=document.getElementById("overview-hosts");
  hosts.slice(0,4).forEach(h=>appendDemoHost(preview,h));
  const tbody=document.getElementById("hosts-body");
  hosts.forEach(h=>{
    const tr=element("tr");
    [h.hostname,h.address,h.group,h.os,h.firewall].forEach((value,index)=>{
      const td=element("td");td.append(element(index===0?"strong":"span",value));tr.append(td);
    });
    const td=element("td");td.append(element("span",h.selinux,h.selinux==="Enforcing"?"chip":"chip warning"));tr.append(td);tbody.append(tr);
    appendDemoHost(document.getElementById("selinux-hosts"),h);
  });
}
function renderPolicies(policies) {
  const tbody=document.getElementById("policies-body");
  policies.forEach(p=>{
    const tr=element("tr");
    [p.name,p.target,p.rules,p.revision].forEach(v=>tr.append(element("td",v)));
    const td=element("td");td.append(element("span",p.state,"chip neutral"));tr.append(td);tbody.append(tr);
  });
}
async function getJSON(url) {
  const response=await fetch(url,{cache:"no-store"});
  if(!response.ok)throw new Error(`${response.status}: ${url}`);
  return response.json();
}
async function loadDemo() {
  try {
    const [summary,hosts,policies]=await Promise.all([
      getJSON("/api/v1/summary"),getJSON("/api/v1/hosts"),getJSON("/api/v1/policies")
    ]);
    document.getElementById("summary-hosts").textContent=summary.hosts;
    document.getElementById("summary-policies").textContent=summary.policy_sets;
    document.getElementById("summary-enforcing").textContent=summary.enforcing+" / "+summary.hosts;
    renderHosts(hosts.items);renderPolicies(policies.items);
  } catch(e) {
    console.error("NixFence demo API unavailable",e);
    document.getElementById("overview-hosts").textContent="Demo API is unavailable. Check the server process.";
  }
}
const editor=document.getElementById("policy-json");
editor.value=JSON.stringify(SAMPLE_POLICY,null,2);
document.getElementById("reset-policy").addEventListener("click",()=>{editor.value=JSON.stringify(SAMPLE_POLICY,null,2);document.getElementById("analysis-results").textContent="Example reset. Run analysis again."});
document.getElementById("analyze-button").addEventListener("click",async()=>{
  const target=document.getElementById("analysis-results");target.replaceChildren();
  let input;
  try{input=JSON.parse(editor.value);}catch(e){target.append(element("p","Invalid JSON: "+e.message,"issue error"));return;}
  try {
    const response=await fetch("/api/v1/policies/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(input)});
    const result=await response.json();
    if(!response.ok){
      const message=response.status===422?"Schema validation failed. Review field names, CIDRs, and port/protocol combinations.":"Analysis failed.";
      target.append(element("p",message,"issue error"));
      if(result.detail){
        result.detail.slice(0,6).forEach(issue=>target.append(element("p",`${(issue.loc||[]).join(".")}: ${issue.msg}`,"issue error")));
      }
      return;
    }
    target.className="analysis-output";
    const summaries=element("div",null,"result-summary");
    [["Rules",result.rule_count],["Enabled",result.enabled_rule_count],["Warnings",result.issues.length]].forEach(([label,value])=>{
      const metric=element("div");metric.append(element("b",value),element("span",label));summaries.append(metric);
    });target.append(summaries);
    if(!result.issues.length)target.append(element("div","No issues found by these preliminary heuristics. Not a deployment safety guarantee.","issue"));
    result.issues.forEach(issue=>{
      const node=element("div",null,"issue "+issue.severity);
      node.append(element("b",issue.code+(issue.rule_id?" · "+issue.rule_id:"")),element("p",issue.message));target.append(node);
    });
    target.append(element("p","Analysis only • No remote execution • No changes applied","analysis-note"));
  } catch(e){target.append(element("p","Could not contact policy analysis API: "+e.message,"issue error"));}
});
loadDemo();
