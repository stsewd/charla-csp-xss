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
