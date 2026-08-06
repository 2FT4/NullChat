// Script de diagnostic : envoie un e-mail de test avec les identifiants
// du .env, en dehors de toute logique de l'app, pour isoler le problème.
//
// Utilisation (à la racine du projet, à côté de server.js et .env) :
//   npm install nodemailer dotenv   (si pas déjà fait)
//   node test-email.js
//
// Lis bien TOUT ce qui s'affiche dans la console, y compris en cas de
// "succès" apparent (vérifie le "accepted" à la fin).

require('dotenv').config();
const nodemailer = require('nodemailer');

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

console.log('--- Diagnostic e-mail NullChat ---');
console.log('EMAIL_USER lu depuis .env :', EMAIL_USER || '(VIDE — .env non chargé ou mal placé !)');
console.log('EMAIL_PASS lu depuis .env :', EMAIL_PASS ? '*'.repeat(EMAIL_PASS.length) + ` (${EMAIL_PASS.length} caractères)` : '(VIDE — .env non chargé ou mal placé !)');

if (!EMAIL_USER || !EMAIL_PASS) {
  console.log('\n❌ Le .env ne se charge pas. Vérifie qu\'il est bien à la racine du projet,');
  console.log('   au même niveau que server.js, et qu\'il contient exactement :');
  console.log('   EMAIL_USER=ton@email.com');
  console.log('   EMAIL_PASS=xxxx xxxx xxxx xxxx');
  process.exit(1);
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
});

async function main() {
  console.log('\nÉtape 1 : vérification des identifiants auprès de Gmail...');
  try {
    await transporter.verify();
    console.log('✅ Identifiants acceptés par Gmail.');
  } catch (e) {
    console.log('❌ Échec d\'authentification :', e.message);
    console.log('   -> Vérifie que c\'est bien un "mot de passe d\'application" Google');
    console.log('      (16 caractères), généré depuis myaccount.google.com/apppasswords,');
    console.log('      PAS ton mot de passe Gmail normal. Il faut aussi que la validation');
    console.log('      en 2 étapes soit activée sur le compte Google pour pouvoir en créer un.');
    process.exit(1);
  }

  console.log('\nÉtape 2 : envoi d\'un e-mail de test à', EMAIL_USER, '...');
  try {
    const info = await transporter.sendMail({
      from: `"NullChat (test)" <${EMAIL_USER}>`,
      to: EMAIL_USER,
      subject: 'Test NullChat 2FA',
      text: 'Si tu reçois ceci (même dans les spams), l\'envoi fonctionne.'
    });
    console.log('Réponse du serveur SMTP :', JSON.stringify(info, null, 2));
    if (info.accepted && info.accepted.length > 0 && (!info.rejected || info.rejected.length === 0)) {
      console.log('\n✅ Gmail a ACCEPTÉ le message pour livraison (accepted:', info.accepted.join(','), ').');
      console.log('   S\'il n\'apparaît toujours pas dans quelques minutes : regarde');
      console.log('   l\'onglet "Spam", l\'onglet "Promotions", et l\'onglet "Tous les messages"');
      console.log('   (un envoi à soi-même part parfois directement dans "Envoyés" sans jamais');
      console.log('   apparaître comme reçu, selon les filtres Gmail).');
    } else {
      console.log('\n❌ Gmail a REFUSÉ ou n\'a accepté personne (rejected:', (info.rejected||[]).join(','), ').');
    }
  } catch (e) {
    console.log('❌ Erreur lors de l\'envoi :', e.message);
    console.log('   Code:', e.code, '| Command:', e.command);
  }
}

main();
