// Extract the English reference catalogue from the instrumented pages.
// Sources of keys:
//  - data-i18n="k">TEXT           (first text node / textContent)
//  - data-i18n-html="k">…</div>   (rich text, markup kept)
//  - data-i18n-title="k" + title="…"
//  - data-i18n-placeholder="k" + placeholder="…"
//  - t('k','default') / t2('k','default') in JS (t2 is an alias)
//  - tn('base',n,'one','many') → base.one / base.many
// Plus hand-maintained lists: dynamic-key families (status.*, err.*,
// bench.bn.*) whose keys are computed at runtime.
//
// Plurals: English (the reference) has just the CLDR one|other categories,
// stored as base.one / base.many (".many" is the historical suffix for the
// non-one bucket). tn() at runtime selects via Intl.PluralRules, and Slavic
// catalogues add a base.few form by hand - that extra category is per-locale
// and never appears in this English reference, so it isn't scraped here.
// check.py validates per-locale plural-category completeness against the
// base.one/base.many families this file emits.
const fs = require('fs');
const files = ['web/dashboard.html', 'web/wall.html'];
const out = {};
const clash = [];
function put(k, v) {
  v = v.replace(/\s+/g, ' ').trim();
  if (k in out && out[k] !== v) clash.push([k, out[k], v]);
  else out[k] = v;
}
const decode = s => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<')
  .replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#10;/g, '\n');
const unesc = s => s.replace(/\\(['"\\n])/g, (m, c) => c === 'n' ? '\n' : c);

for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  // element text. Two guards keep JS out of the scrape: keys are dotted
  // identifiers ([\w.\-]+, so `data-i18n="${k}"` template literals are
  // skipped), and the (?<!\[) lookbehind rejects attribute-SELECTOR uses
  // like `querySelector('a[data-i18n="hdr.manual"]')` - in real HTML the
  // attribute is preceded by whitespace, never by '['. Without these the
  // injected contextual-help code was scraped as bogus keys / giant values.
  for (const m of s.matchAll(/(?<!\[)data-i18n="([\w.\-]+)"[^>]*>([^<]*)/g)) {
    const txt = decode(m[2]);
    if (txt.trim()) put(m[1], txt);
    else if (!(m[1] in out)) clash.push([m[1], '<EMPTY TEXT>', f]);
  }
  // rich text (-html sites are <div>…</div> or <p>…</p> with no nested div/p)
  for (const m of s.matchAll(/(?<!\[)data-i18n-html="([\w.\-]+)"[^>]*>([\s\S]*?)<\/(?:div|p)>/g))
    put(m[1], m[2]);
  // attribute pairs. One element can carry BOTH (the ladder-N input has a
  // data-i18n-placeholder AND a data-i18n-title): match the whole tag once,
  // then walk every data-i18n-<which> it declares. The old code took the
  // FIRST attribute only, so ladder.n.title never reached the reference and
  // rendered English in all 27 locales with every gate green.
  for (const m of s.matchAll(/<[^>]*data-i18n-(?:title|placeholder)="[\w.\-]+"[^>]*>/g)) {
    const tag = m[0];
    for (const a of tag.matchAll(/data-i18n-(title|placeholder)="([\w.\-]+)"/g)) {
      const which = a[1], k = a[2];
      const v = tag.match(new RegExp('(?<!data-i18n-)' + which + '="([^"]*)"'));
      if (v) put(k, decode(v[1]));
      else clash.push([k, '<NO ' + which + ' ATTR>', f]);
    }
  }
  // t('key','default')
  // t2 is an alias for t, used where a local `t` shadows the helper. It
  // was not scraped, so its keys never reached any catalogue and fell
  // back to English at runtime (toast.lookreset had been missing since
  // it was written).
  for (const m of s.matchAll(/\bt2?\(\s*(['"])([\w.\-]+)\1\s*,\s*(')((?:\\.|[^'\\])*)'|\bt2?\(\s*(['"])([\w.\-]+)\5\s*,\s*(")((?:\\.|[^"\\])*)"/g)) {
    const k = m[2] ?? m[6], d = m[4] ?? m[8];
    put(k, unesc(d));
  }
  // tn('base',expr,'one','many')
  for (const m of s.matchAll(/\btn\(\s*'([\w.\-]+)'\s*,\s*[^,]+,\s*(['"])((?:\\.|(?!\2).)*)\2\s*,\s*(['"])((?:\\.|(?!\4).)*)\4/g)) {
    put(m[1] + '.one', unesc(m[3]));
    put(m[1] + '.many', unesc(m[5]));
  }
}

// Dynamic-key families (computed at runtime, no literal to scrape).
Object.assign(out, {
  // §Stage2 settings rail: the group names live in the SETGROUPS table and
  // are rendered via t(g.i, g.d), so the key is a variable at the call site
  // and the scrape above cannot see it.
  'set.g.start': 'Getting started',
  'set.g.download': 'Downloading',
  'set.g.organise': 'Organising',
  'set.g.alerts': 'Alerts',
  'set.g.look': 'Look and feel',
  'set.g.system': 'System',
  // hist.vh: t(totBad===1?'hist.vh.bad.one':…)
  'hist.vh.bad.one': '{n} bad block across the last {m}',
  'hist.vh.bad.many': '{n} bad blocks across the last {m}',
  // Archive-shape badge tokens: rendered via t('shape.'+tok, SHAPE_EN[tok])
  // from the daemon's token list, so the key is computed at the call site.
  'shape.rar5': 'RAR5', 'shape.rar4': 'RAR4', 'shape.7z': '7z', 'shape.zip': 'zip',
  'shape.store': 'stored', 'shape.compressed': 'compressed', 'shape.mixed': 'mixed',
  'shape.encrypted': 'encrypted',
  'shape.one-pass': 'one-pass', 'shape.unlock-at-end': 'unlocked at the end',
  'shape.on-disk': 'unpacked after download', 'shape.mixed-pass': 'partly on disk',
  'shape.inner-7z': '7z inside', 'shape.inner-rar': 'RAR inside',
  // Post-age buckets: rendered via t('pq.age.b'+key, AGE_EN[key]) from
  // the daemon's own bucket key, so the key is computed at the call
  // site and the scrape above cannot see it. The RANGES are
  // nzbkit::oracle::age_bucket's and must not move here; what a
  // catalogue translates is the day/year marker.
  'pq.age.b0': '0-1d', 'pq.age.b1': '1-7d', 'pq.age.b2': '7-30d',
  'pq.age.b3': '30-90d', 'pq.age.b4': '90-365d', 'pq.age.b5': '1-3y',
  'pq.age.b6': '3y+',
  // sysbench bottleneck tags
  'bench.bn.network': 'network', 'bench.bn.compute': 'compute', 'bench.bn.disk': 'disk',
  // Speed units: rendered via unit(k) = t('unit.'+k, UNIT_EN[k]). Latin
  // scripts keep the SI abbreviations; Cyrillic/Greek localize (e.g. ГБ/с).
  'unit.MB': 'MB', 'unit.GB': 'GB', 'unit.TB': 'TB',
  // ...and the 1024-based trio, which release sizes are quoted in
  // everywhere in this world (indexers, SABnzbd, our own `mb` field).
  // fmtMB divides by 1024 and now says so; it used to divide by 1024 and
  // print "GB" beside decimal disk-space readouts calling different
  // bytes the same name.
  'unit.MiB': 'MiB', 'unit.GiB': 'GiB', 'unit.TiB': 'TiB',
  'unit.MBs': 'MB/s', 'unit.GBs': 'GB/s', 'unit.Mbs': 'Mb/s', 'unit.Gbs': 'Gb/s',
  // Group-browser column headings: gbHead() renders each one through a
  // local col(cls,key,def,sort) helper, so t() is called with a variable.
  // The other five (group/vol/avg/act/last) are scraped only because the
  // group DETAIL panel happens to repeat them as literals - grp.h.kind is
  // used nowhere else, so it was invisible.
  'grp.h.kind': 'Content',
  // Wall section headings: KINDLBL maps a kind slug to [key, English] and
  // kindHead() calls t(key,en). wall.cat.apps rode in on a separate literal
  // t() call; its three siblings had no literal anywhere.
  'wall.cat.tv': 'TV shows', 'wall.cat.movies': 'Movies',
  'wall.cat.other': 'Other',
  // Group-browser category chips: rendered via t('grp.cat.'+c, GB_CAT_EN[c])
  'grp.cat.all': 'All', 'grp.cat.movies': 'Movies', 'grp.cat.tv': 'TV',
  'grp.cat.music': 'Music', 'grp.cat.books': 'Books', 'grp.cat.comics': 'Comics',
  'grp.cat.games': 'Games', 'grp.cat.software': 'Software', 'grp.cat.anime': 'Anime',
  'grp.cat.sports': 'Sports & motors', 'grp.cat.adult': 'Adult', 'grp.cat.other': 'Other',
  // Sounds card event labels: rendered via t('snd.ev.'+key, SND[key].label)
  'snd.ev.click': 'Button press', 'snd.ev.added': 'Download added',
  'snd.ev.watchlist': 'Watchlist grab', 'snd.ev.complete': 'Download complete',
  'snd.ev.alldone': 'Queue finished', 'snd.ev.failed': 'Download failed',
  'snd.ev.password': 'Password needed', 'snd.ev.pause': 'Paused / resumed',
  'snd.ev.conn': 'Connection lost / restored', 'snd.ev.update': 'Update available',
  'snd.ev.warn': 'Warning', 'snd.ev.refuse': 'Error or refused action',
  // INTEREST_LABELS: the opt-in indexing choices. Built from a table
  // keyed by the daemon's interest keys, so t() is called with a
  // variable and the scraper cannot see them.
  'idx.want.linux': 'Linux and other freely distributable software',
  'idx.want.movies': 'Films',
  'idx.want.tv': 'TV shows',
  'idx.want.sports': 'Sport',
  'idx.want.music': 'Music',
  'idx.want.books': 'Books and audiobooks',
  'idx.want.comics': 'Comics',
  'idx.want.anime': 'Anime',
  'idx.want.games': 'Games',
  'idx.want.apps': 'Applications',
  // tStatus(): SAB-compatible wire statuses (English stays on the wire)
  'status.Downloading': 'Downloading', 'status.Queued': 'Queued',
  'status.Paused': 'Paused', 'status.Completed': 'Completed',
  'status.Failed': 'Failed', 'status.Idle': 'Idle', 'status.idle': 'idle',
  // The post-network tail, reported per phase by the pipeline itself.
  // SABnzbd's own state words, so the *arrs read them unchanged.
  'status.Verifying': 'Verifying', 'status.Repairing': 'Repairing',
  'status.Extracting': 'Extracting', 'status.Moving': 'Moving',
  // renderBusyChips(): header chip strip for background subsystems
  // (stats.busy tokens from the daemon - tokens, never sentences).
  // Own chip.* namespace: busy.* is the button busy-state family.
  // The bare key is the one/two-word CHIP LABEL (header space is
  // scarce); the .hint key is its tooltip sentence.
  'chip.indexing': 'indexing',
  'chip.enriching': 'metadata',
  'chip.predb': 'release feed',
  'chip.watchlist': 'watchlist',
  'chip.moving': 'moving',
  'chip.maintenance': 'upkeep',
  'chip.measuring': 'measuring',
  'chip.indexing.hint': 'indexing',
  'chip.enriching.hint': 'fetching metadata',
  'chip.predb.hint': 'syncing release feed',
  'chip.watchlist.hint': 'checking watchlist',
  'chip.moving.hint': 'moving files',
  'chip.maintenance.hint': 'database upkeep',
  'chip.measuring.hint': 'measuring connections',
  'chip.listsync': 'lists',
  'chip.listsync.hint': 'syncing your lists',
  // ...and what each chip's menu offers. BUSY_ACTS is a table of
  // [key, English, javascript] rows, so every one of these is a literal
  // in an ARRAY rather than an argument to t() and the scrape cannot
  // see it - the same reason SETGROUPS is listed at the top of this
  // block. chip.nostop is the sentence the three subsystems with no off
  // switch show in place of one.
  'chip.act.settings': 'Open its settings',
  'chip.act.idxoff': 'Turn indexing off',
  'chip.act.metapause': 'Pause metadata lookups',
  'chip.act.predboff': 'Turn the release feed off',
  'chip.act.watch': 'Open the watchlist',
  'chip.act.lists': 'Open list sources',
  'chip.act.tuneoff': 'Stop measuring connections',
  'chip.act.queue': 'Show the queue',
  'chip.nostop': 'Finishes on its own - nothing to switch off',
  // The queue pill's own menu, same table shape.
  'chip.q.pausenow': 'Pause now',
  // TODO 274 drawer file list: the engine's per-file state word, rendered
  // via t(...JF_STATE[state]) from the token the daemon sent, so the key
  // is a table lookup at the call site and the scrape cannot see it.
  'drawer.fs.queued': 'waiting',
  'drawer.fs.active': 'downloading',
  'drawer.fs.complete': 'done',
  'drawer.fs.deferred': 'skipped',
  'drawer.fs.damaged': 'damaged',
  'drawer.fs.recovery': 'repair data',
  'drawer.fs.published': 'at destination',
  // tErr(): fixed daemon error strings (serve.rs), keyed by wire text
  'err.unknown nzo_id': 'unknown nzo_id',
  'err.empty password': 'empty password',
  'err.POST required': 'POST required',
  'err.text too long': 'text too long',
  'err.invalid folder name': 'invalid folder name',
  'err.no nzb file in request': 'no nzb file in request',
  'err.empty query': 'empty query',
  'err.index unavailable': 'index unavailable',
  'err.key and title are required': 'key and title are required',
  'err.key is required': 'key is required',
  'err.unknown title key': 'unknown title key',
  'err.image too large (8 MB max)': 'image too large (8 MB max)',
  "err.that isn't an image (JPEG/PNG/GIF/WebP)": "that isn't an image (JPEG/PNG/GIF/WebP)",
  "err.couldn't write the art cache": "couldn't write the art cache",
  'err.a valid email address is required': 'a valid email address is required',
  'err.release not found': 'release not found',
  'err.cannot move the active download': 'cannot move the active download',
  'err.this job is still finishing': 'this job is still finishing',
  'err.no servers configured': 'no servers configured',
  'err.no such server': 'no such server',
  'err.unknown server index': 'unknown server index',
  'err.connect timed out (12 s)': 'connect timed out (12 s)',
  // The two delete arms in api/queue/payload.rs. Both answer a
  // request that matched no row, and both used to answer it with no
  // `error` at all - which the dashboard's three bulk delete controls
  // read as success and reported in green. They are two sentences and
  // not one because "may have just finished" is true of a queued row
  // and false of a history row, which by definition finished long ago.
  'err.nothing in the queue matched that - it may have just finished, or been removed already':
    'nothing in the queue matched that - it may have just finished, or been removed already',
  'err.nothing in your history matched that - it may have been removed already':
    'nothing in your history matched that - it may have been removed already',
  // M32 route controls (serve/servers.rs): these landed in the
  // reference by hand without joining this list, so the next regen
  // silently dropped them - they must live HERE to survive extract.
  'err.bind address: not an IP address': 'bind address: not an IP address',
  'err.proxy address: expected host:port': 'proxy address: expected host:port',
  'err.proxy address: put the user and password in their own boxes':
    'proxy address: put the user and password in their own boxes',
  'err.move failed (files in use, or target exists?)': 'move failed (files in use, or target exists?)',
  // M32's route controls. These reach the form through the same tErr()
  // path; hand-editing them into en.reference.json instead left them out
  // of this list, so the next extract silently dropped all three
  // (Codex sweep 7, L4).
  'err.bind address: not an IP address': 'bind address: not an IP address',
  'err.proxy address: expected host:port': 'proxy address: expected host:port',
  'err.proxy address: put the user and password in their own boxes':
    'proxy address: put the user and password in their own boxes',
  // IndexBusy::message() (serve/daemon_index.rs): the two transient
  // "ask again" answers from the index read path. The read handlers have
  // emitted them since they shipped; TODO 166 widened their reach to
  // every user-WRITE handler in api/wall.rs and api/index.rs
  // (wall_fix, wall_art, wall_refresh, wall_merge, wall_hide/unhide,
  // wall_rule_add/del, wall_suggest_no, pre_assign, pre_reject,
  // rar_name), which is when 27 locales showing English became worth
  // fixing. tErr() keys on the wire text, so the key IS the sentence.
  'err.the index is busy - try again in a moment':
    'the index is busy - try again in a moment',
  'err.the index schema changed mid-query - try again in a moment':
    'the index schema changed mid-query - try again in a moment',
  // Not from serve.rs: api() mints this one when the request never gets
  // an answer at all (ERR_UNREACHABLE), so it rides the same tErr() path
  // as the wire strings.
  'err.could not reach nzbfast': 'could not reach nzbfast',
});

// Plural families must ship BOTH English categories (base.one + base.many);
// check.py infers the family set from exactly this invariant, so a lone .one
// or .many (a typo'd tn() call) would silently break per-locale validation.
for (const k of Object.keys(out)) {
  if (k.endsWith('.one') && !(k.slice(0, -4) + '.many' in out))
    clash.push([k, '<PLURAL .one WITHOUT MATCHING .many>', '']);
  if (k.endsWith('.many') && !(k.slice(0, -5) + '.one' in out))
    clash.push([k, '<PLURAL .many WITHOUT MATCHING .one>', '']);
}

if (clash.length) { console.error('CLASHES/GAPS:'); for (const c of clash) console.error(' ', c); }
const sorted = {};
for (const k of Object.keys(out).sort()) sorted[k] = out[k];
fs.writeFileSync('web/i18n/en.reference.json', JSON.stringify(sorted, null, 1) + '\n');
console.log(Object.keys(sorted).length + ' keys → web/i18n/en.reference.json');
