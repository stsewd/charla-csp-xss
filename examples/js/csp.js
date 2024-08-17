let csp = document.getElementById("csp").content;
// Split by space, indennt with two spaces, and join by newline.
csp = csp.split(';').join(';\n');
csp = csp.split(' ').join('\n  ');
document.getElementById('csp-content').innerText = csp;
