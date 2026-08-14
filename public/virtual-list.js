// ==========================================
// virtual-list.js — Liste de messages virtualisée, vanilla JS, zéro dépendance
// ==========================================
// Principe : un seul scroll container. On ne matérialise dans le DOM que les
// messages dont la fenêtre [scrollTop, scrollTop+viewportHeight] les rend
// visibles (+ un buffer au-dessus/dessous pour un scroll fluide). Le reste de
// la liste est simulé par deux "spacers" (haut/bas) dont la hauteur = somme
// des hauteurs des messages non montés. Les médias (images/vidéos) des
// messages qui sortent du buffer sont explicitement détachés (src vidé) pour
// que le navigateur libère la RAM associée au décodage — c'est le point
// "zéro-memory-leak" : rien ne s'accumule indéfiniment en mémoire au fil
// d'une longue session.
//
// Intégration dans NulChat : ce module ne connaît rien du format des messages
// NulChat. On lui donne juste (a) la liste de données, (b) une fonction qui
// construit le DOM d'un message (réutilise vos fonctions existantes comme
// addChatMessage / attachMessageInteractions), et (c) une hauteur estimée par
// défaut (les hauteurs réelles sont mesurées après montage et mises en cache).
//
// Usage minimal :
//   const vlist = new VirtualMessageList({
//     container: document.getElementById('serverMessages'),
//     estimateHeight: 56,
//     buffer: 6, // nb de messages supplémentaires montés au-dessus/dessous
//     renderItem: (entry) => buildMessageNode(entry), // renvoie un HTMLElement
//     onUnmount: (node) => { // libère la RAM média
//       node.querySelectorAll('img,video').forEach(m => { m.src = ''; m.removeAttribute('src'); });
//     }
//   });
//   vlist.setItems(messages);       // (re)donne la liste complète
//   vlist.push(newMessage);         // ajoute un message en fin de liste
//   vlist.scrollToBottom();

class VirtualMessageList {
  constructor({ container, renderItem, onUnmount, estimateHeight = 56, buffer = 6, getId }) {
    this.container = container;
    this.renderItem = renderItem;
    this.onUnmount = onUnmount || (() => {});
    this.getId = getId || ((item, i) => item.id ?? i);
    this.estimateHeight = estimateHeight;
    this.buffer = buffer;

    this.items = [];
    this.heights = new Map();   // id -> hauteur mesurée réelle (px)
    this.mounted = new Map();   // id -> { node, index }
    this.stickToBottom = true;  // suit les nouveaux messages tant que l'utilisateur n'a pas remonté

    // Structure DOM : container (scrollable) > viewport (position:relative) > spacerTop / spacerBottom / (nodes montés)
    this.container.style.overflowY = 'auto';
    this.container.style.position = 'relative';
    this.viewport = document.createElement('div');
    this.viewport.style.position = 'relative';
    this.container.innerHTML = '';
    this.container.appendChild(this.viewport);

    this.spacerTop = document.createElement('div');
    this.spacerBottom = document.createElement('div');
    this.viewport.appendChild(this.spacerTop);
    this.viewport.appendChild(this.spacerBottom);

    this._onScroll = this._onScroll.bind(this);
    this.container.addEventListener('scroll', this._onScroll, { passive: true });

    this._resizeObserver = new ResizeObserver(() => this._render());
    this._resizeObserver.observe(this.container);
  }

  setItems(items){
    this.items = items;
    // Nettoie les hauteurs de messages qui n'existent plus (suppression, purge éphémère)
    const idSet = new Set(items.map((it, i) => this.getId(it, i)));
    for (const id of this.heights.keys()) if (!idSet.has(id)) this.heights.delete(id);
    this._render(true);
  }

  push(item){
    this.items.push(item);
    this._render(this.stickToBottom);
  }

  removeById(id){
    this.items = this.items.filter((it, i) => this.getId(it, i) !== id);
    this.heights.delete(id);
    this._render(false);
  }

  scrollToBottom(){
    this.stickToBottom = true;
    this.container.scrollTop = this.container.scrollHeight;
    this._render(true);
  }

  destroy(){
    this.container.removeEventListener('scroll', this._onScroll);
    this._resizeObserver.disconnect();
    for (const { node } of this.mounted.values()) this.onUnmount(node);
    this.mounted.clear();
  }

  _onScroll(){
    // Détecte si l'utilisateur est proche du bas pour décider si on continue
    // à "coller" aux nouveaux messages entrants.
    const { scrollTop, scrollHeight, clientHeight } = this.container;
    this.stickToBottom = scrollHeight - (scrollTop + clientHeight) < 80;
    this._render(false);
  }

  _heightOf(id){
    return this.heights.get(id) ?? this.estimateHeight;
  }

  _render(forceStickCheck){
    const n = this.items.length;
    if (n === 0){
      this.spacerTop.style.height = '0px';
      this.spacerBottom.style.height = '0px';
      for (const { node } of this.mounted.values()) { this.onUnmount(node); node.remove(); }
      this.mounted.clear();
      return;
    }

    // 1) Calcule les offsets cumulés (top de chaque message) à partir des
    //    hauteurs connues/estimées — O(n) mais uniquement des additions, donc
    //    négligeable même pour plusieurs dizaines de milliers de messages.
    const offsets = new Array(n);
    let acc = 0;
    for (let i = 0; i < n; i++){
      offsets[i] = acc;
      acc += this._heightOf(this.getId(this.items[i], i));
    }
    const totalHeight = acc;

    const viewportH = this.container.clientHeight || 600;
    const scrollTop = forceStickCheck && this.stickToBottom ? totalHeight : this.container.scrollTop;

    // 2) Trouve la fenêtre de messages visibles via recherche binaire sur offsets.
    const lo = this._binarySearch(offsets, scrollTop - viewportH * 1.5);
    const hi = this._binarySearch(offsets, scrollTop + viewportH * 1.5);
    const startIdx = Math.max(0, lo - this.buffer);
    const endIdx = Math.min(n - 1, hi + this.buffer);

    // 3) Démonte tout ce qui sort de la fenêtre -> libère la RAM (images/vidéos).
    for (const [id, entry] of this.mounted){
      if (entry.index < startIdx || entry.index > endIdx){
        this.onUnmount(entry.node);
        entry.node.remove();
        this.mounted.delete(id);
      }
    }

    // 4) Monte ce qui manque dans la fenêtre, mesure sa vraie hauteur.
    for (let i = startIdx; i <= endIdx; i++){
      const id = this.getId(this.items[i], i);
      if (this.mounted.has(id)) { this.mounted.get(id).index = i; continue; }
      const node = this.renderItem(this.items[i], i);
      node.style.position = 'absolute';
      node.style.left = '0';
      node.style.right = '0';
      node.style.top = offsets[i] + 'px';
      this.viewport.insertBefore(node, this.spacerBottom);
      this.mounted.set(id, { node, index: i });
      // Mesure post-montage (layout réel : reply-quotes, images chargées, etc.)
      requestAnimationFrame(() => {
        const h = node.getBoundingClientRect().height;
        if (h > 0 && Math.abs(h - this._heightOf(id)) > 1){
          this.heights.set(id, h);
          this._render(false); // recalcule les offsets suivants avec la vraie hauteur
        }
      });
    }

    // 5) Repositionne tous les nœuds montés (les offsets ont pu bouger après mesure).
    for (const [id, entry] of this.mounted){
      entry.node.style.top = offsets[entry.index] + 'px';
    }

    this.viewport.style.height = totalHeight + 'px';
    this.spacerTop.style.height = '0px';
    this.spacerBottom.style.height = '0px';

    if (forceStickCheck && this.stickToBottom){
      this.container.scrollTop = totalHeight;
    }
  }

  _binarySearch(offsets, target){
    let low = 0, high = offsets.length - 1;
    while (low < high){
      const mid = (low + high) >> 1;
      if (offsets[mid] < target) low = mid + 1; else high = mid;
    }
    return low;
  }
}

// Exposé globalement pour un <script src="/virtual-list.js"> classique (NulChat
// n'utilise pas de bundler / modules ES côté client).
window.VirtualMessageList = VirtualMessageList;
