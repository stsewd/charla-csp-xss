window.onload = function () {
  let csp = document.getElementById("csp").content;
  // Split by space, indennt with two spaces, and join by newline.
  csp = csp.split(' ').join('\n  ');

  document.getElementById('csp-content').innerText = csp;

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

  function loadDarkMode() {
    const toggle = document.getElementById('dark-mode-toggle');
    const darkMode = localStorage.getItem('dark-mode');
    toggle.checked = darkMode === 'true';
    document.documentElement.setAttribute('data-theme', toggle.checked ? 'dark' : 'light');
  }

  function toggleDarkMode() {
    const toggle = document.getElementById('dark-mode-toggle');
    document.documentElement.setAttribute('data-theme', toggle.checked ? 'dark' : 'light');
    localStorage.setItem('dark-mode', toggle.checked ? 'true' : 'false');
  }

  loadDarkMode();
  document.getElementById('dark-mode-toggle').addEventListener('click', function () {
    toggleDarkMode();
  });

  document.addEventListener("securitypolicyviolation", (e) => {
    const error = `Blocked URI: ${e.blockedURI}\nViolated Directive: ${e.violatedDirective}\nDocument URI: ${e.documentURI}\nEffective Directive: ${e.effectiveDirective}\nSample: ${e.sample}\n`;
    const log = document.getElementById("errors");
    log.innerText = error;
  });
}
