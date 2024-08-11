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

  function toggleDarkMode() {
    const toggle = document.getElementById('dark-mode-toggle');
    document.documentElement.setAttribute('data-theme', toggle.checked ? 'dark' : 'light');
  }

  toggleDarkMode();
  const toggle = document.getElementById('dark-mode-toggle');
  toggle.addEventListener('click', function () {
    toggleDarkMode();
  });
}
