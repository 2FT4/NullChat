// ==========================================
// audio-worker.js — Détection de voix (VAD) hors thread principal
// ==========================================
// Tourne dans un Web Worker dédié : reçoit des frames PCM Float32 transférables
// (zero-copy) depuis le thread UI, calcule une énergie RMS + un seuil adaptatif
// avec hystérésis (attaque rapide / relâchement lent, comme un noise gate audio
// pro) et renvoie uniquement un booléen "speaking". Aucun DOM, aucun rendu :
// ce fichier ne peut structurellement pas faire chuter le framerate de l'UI.
//
// Migration WASM : cette implémentation JS pure suffit pour un gate VAD fiable
// à faible coût CPU. Pour une suppression de bruit plus poussée (RNNoise), il
// suffit de charger un module .wasm ici (WebAssembly.instantiateStreaming) et
// de router les frames à travers lui avant le calcul RMS — l'API postMessage
// vue par le thread principal ne change pas.

let noiseFloor = 0.0015;      // bruit ambiant estimé, mis à jour en continu
let smoothedEnergy = 0;
let speaking = false;
let hangoverFrames = 0;       // évite le hachage ("choppy mute") en fin de phrase

const ATTACK = 0.6;           // réactivité à la montée (parle -> détecté vite)
const RELEASE = 0.05;         // lissage à la descente (évite les faux négatifs)
const HANGOVER_FRAMES = 8;    // ~ 8 * 2048 samples @48kHz ≈ 340ms de tolérance
const SPEECH_MULTIPLIER = 3.2; // seuil = bruit ambiant * ce facteur

function rms(samples){
  let sum = 0;
  for (let i = 0; i < samples.length; i++) sum += samples[i] * samples[i];
  return Math.sqrt(sum / samples.length);
}

self.onmessage = (e) => {
  const { type, samples } = e.data;
  if (type !== 'frame') return;

  const energy = rms(samples);

  // Mise à jour du plancher de bruit uniquement quand on n'est pas en train
  // de parler, pour s'adapter à l'environnement (clim, ventilo, etc.) sans
  // jamais "apprendre" la voix comme du bruit.
  if (!speaking){
    noiseFloor = noiseFloor * 0.98 + energy * 0.02;
  }

  smoothedEnergy = energy > smoothedEnergy
    ? smoothedEnergy + (energy - smoothedEnergy) * ATTACK
    : smoothedEnergy + (energy - smoothedEnergy) * RELEASE;

  const threshold = Math.max(noiseFloor * SPEECH_MULTIPLIER, 0.003);
  const isLoudEnough = smoothedEnergy > threshold;

  if (isLoudEnough){
    hangoverFrames = HANGOVER_FRAMES;
  } else if (hangoverFrames > 0){
    hangoverFrames--;
  }

  const nextSpeaking = hangoverFrames > 0;
  if (nextSpeaking !== speaking){
    speaking = nextSpeaking;
    self.postMessage({ type: 'vad', speaking });
  }
};
