// Defensa contra XSS basado en DOM: textContent trata el valor como TEXTO,
// nunca como HTML. (La versión vulnerable asigna el valor como HTML.)
const t = document.getElementById('texto');
const p = document.getElementById('preview');
t.addEventListener('input', () => { p.textContent = t.value; });
