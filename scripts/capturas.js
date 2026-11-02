// Capturas de pantalla de evidencia con Chromium (Playwright).
// Uso: node scripts/capturas.js   (servidor corriendo en https://localhost:8443)
const { chromium } = require('playwright');
const fs = require('fs');
const env = Object.fromEntries(fs.readFileSync('.env', 'utf8').split('\n').filter(l => l.includes('=') && !l.startsWith('#')).map(l => [l.split('=')[0], l.slice(l.indexOf('=') + 1)]));
const B = 'https://localhost:8443', D = 'docs/evidencias/';
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1000, height: 640 } });
  const page = await ctx.newPage();
  const alertas = [];
  page.on('dialog', async d => { alertas.push(`${page.url()} -> alert("${d.message()}")`); await d.dismiss(); });
  const banner = async (txt, color) => page.evaluate(([t, c]) => {
    const b = document.createElement('div'); b.textContent = t;
    b.style = `position:fixed;bottom:0;left:0;right:0;padding:8px;font:14px monospace;color:#fff;background:${c}`;
    document.body.appendChild(b);
  }, [txt, color]);

  await page.goto(B + '/login');
  await page.fill('input[name=email]', 'admin@ejemplo.edu.gt');
  await page.fill('input[name=password]', env.ADMIN_INITIAL_PASSWORD);
  await page.click('button.primario');

  // XSS almacenado - versión corregida
  await page.goto(B + '/comentarios');
  await page.fill('#texto', '<img src=x onerror=alert("XSS-almacenado")> <b>negrita?</b>');
  await page.click('button:has-text("Publicar")');
  await page.waitForLoadState();
  await banner(`CORREGIDO · alertas ejecutadas: ${alertas.length} · el payload se muestra como texto`, '#1b7f3b');
  await page.screenshot({ path: D + 'cap_01_xss_corregido.png' });

  // XSS almacenado + reflejado + DOM - versión vulnerable
  const n0 = alertas.length;
  await page.goto(B + '/lab/vuln/comentarios?q=<img src=x onerror=alert("XSS-reflejado")>#<img src=x onerror=alert("XSS-DOM")>');
  await page.waitForTimeout(800);
  await banner(`VULNERABLE · alertas ejecutadas: ${alertas.length - n0} (almacenado + reflejado + DOM)`, '#b3261e');
  await page.screenshot({ path: D + 'cap_02_xss_vulnerable.png' });

  // SQLi
  await page.goto(B + "/lab/vuln/buscar?q=" + encodeURIComponent("x' UNION SELECT clave, valor, 1 FROM config_interna --"));
  await banner('VULNERABLE · UNION SELECT extrae datos de otra tabla', '#b3261e');
  await page.screenshot({ path: D + 'cap_03_sqli_vulnerable.png' });
  await page.goto(B + "/buscar?q=" + encodeURIComponent("x' UNION SELECT clave, valor, 1 FROM config_interna --"));
  await banner('CORREGIDO · la entrada es un dato: 0 resultados', '#1b7f3b');
  await page.screenshot({ path: D + 'cap_04_sqli_corregido.png' });
  await page.goto(B + "/buscar?q=" + encodeURIComponent("O'Brien"));
  await banner("CORREGIDO · búsqueda legítima con apóstrofo funciona", '#1b7f3b');
  await page.screenshot({ path: D + 'cap_05_busqueda_legitima.png' });

  // Expediente con DPI enmascarado
  await page.goto(B + '/expedientes/1290-23-10001');
  await banner('DPI descifrado en servidor y mostrado enmascarado', '#1b7f3b');
  await page.screenshot({ path: D + 'cap_06_expediente.png' });

  // Error interno
  await page.goto(B + '/lab/forzar-error');
  await banner('Error interno: mensaje genérico + código de incidente', '#1b7f3b');
  await page.screenshot({ path: D + 'cap_07_error_generico.png' });

  // Login fallido
  await page.goto(B + '/logout').catch(() => {});
  const c2 = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1000, height: 500 } });
  const p2 = await c2.newPage();
  await p2.goto(B + '/login');
  await p2.fill('input[name=email]', 'admin@ejemplo.edu.gt');
  await p2.fill('input[name=password]', 'Contraseña-Incorrecta');
  await p2.click('button.primario');
  await p2.screenshot({ path: D + 'cap_08_login_fallido.png' });

  fs.writeFileSync(D + 'xss_alertas_navegador.txt', alertas.join('\n') + '\n');
  console.log(alertas.join('\n'));
  await browser.close();
})();
