const template = document.getElementById("payload-template");
let content = template.innerHTML;
html = hljs.highlight(content, {language: 'html'}).value
document.getElementById('payload-content').innerHTML = html;

document.getElementById('inject').addEventListener('click', function () {
  const template = document.getElementById("payload-template");
  const clone = template.content.cloneNode(true);
  const injection = document.getElementById('injection');
  injection.innerHTML = '';
  injection.appendChild(clone);
});

document.addEventListener("securitypolicyviolation", (e) => {
  const error = `Blocked URI: ${e.blockedURI}\nViolated Directive: ${e.violatedDirective}\nDocument URI: ${e.documentURI}\nEffective Directive: ${e.effectiveDirective}\nSample: ${e.sample}\n`;
  const log = document.getElementById("errors");
  log.innerText = error;
});
