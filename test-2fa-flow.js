// Teste directement l'API HTTP (sans navigateur, donc sans cache ni session
// locale qui pourraient fausser le test) :
//   1. Crée un compte de test tout neuf
//   2. Se déconnecte (implicite : on ignore le token d'inscription)
//   3. Appelle VRAIMENT /api/login avec ce compte
//   4. Affiche la réponse brute -> on voit direct si twoFactorRequired apparaît
//
// Utilisation :
//   node test-2fa-flow.js ton@email.com
// (remplace par une adresse que tu peux consulter)

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const testEmail = process.argv[2];

if (!testEmail) {
  console.log('Utilisation : node test-2fa-flow.js ton@email.com');
  process.exit(1);
}

const testUsername = 'test2fa_' + Date.now().toString(36);
const testPassword = 'MotDePasseTest123!';

async function getCaptcha() {
  const res = await fetch(`${BASE_URL}/api/auth/captcha`);
  const data = await res.json();
  console.log('Captcha reçu :', data.code, '(id:', data.captchaId + ')');
  return data;
}

async function main() {
  console.log('=== 1. Inscription du compte de test', testUsername, '===');
  const cap1 = await getCaptcha();
  const regRes = await fetch(`${BASE_URL}/api/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: testUsername,
      password: testPassword,
      email: testEmail,
      captchaId: cap1.captchaId,
      captchaInput: cap1.code
    })
  });
  const regData = await regRes.json();
  console.log('Statut HTTP :', regRes.status);
  console.log('Réponse /api/register :', JSON.stringify(regData, null, 2));

  if (!regRes.ok) {
    console.log('\n❌ L\'inscription a échoué, impossible de tester le login. Regarde l\'erreur ci-dessus.');
    return;
  }

  console.log('\n=== 2. Connexion (VRAI /api/login, pas l\'auto-login de l\'inscription) ===');
  const cap2 = await getCaptcha();
  const loginRes = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: testUsername,
      password: testPassword,
      captchaId: cap2.captchaId,
      captchaInput: cap2.code
    })
  });
  const loginData = await loginRes.json();
  console.log('Statut HTTP :', loginRes.status);
  console.log('Réponse /api/login :', JSON.stringify(loginData, null, 2));

  console.log('\n=== Verdict ===');
  if (loginData.twoFactorRequired) {
    console.log('✅ Le serveur DEMANDE bien un code 2FA (pendingId:', loginData.pendingId + ').');
    console.log('   -> Va vérifier la boîte mail de', testEmail, '(et les spams).');
    console.log('   -> Regarde aussi le terminal de server.js : une ligne');
    console.log('      "Login ... -> e-mail enregistré: ..." et éventuellement');
    console.log('      "E-mail 2FA envoyé, messageId = ..." doivent y être.');
  } else if (loginData.token) {
    console.log('❌ Le serveur a connecté DIRECTEMENT, sans demander de code.');
    console.log('   -> Le bug est donc bien côté serveur (pas le navigateur/cache).');
    console.log('   -> Regarde le terminal de server.js au moment de ce test : la');
    console.log('      ligne "Login ... -> e-mail enregistré: (aucun)" ou');
    console.log('      "mailTransporter configuré: false" dira laquelle des deux');
    console.log('      conditions a bloqué la 2FA.');
  } else {
    console.log('⚠️ Réponse inattendue, regarde le JSON complet ci-dessus.');
  }
}

main().catch(err => {
  console.error('Erreur script :', err);
});
