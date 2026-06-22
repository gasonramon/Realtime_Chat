import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Subject } from 'rxjs';
import { environment } from '../environments/environment';
import { CryptoService } from './crypto.service';

export interface UserSummary { id: string; name: string; }
export interface ChatItem { id: string; fromId: string; fromName: string; toIds: string[]; room: 'global' | 'dm'; text: string; at: string; }

@Injectable({ providedIn: 'root' })
export class ChatService {
  private http = inject(HttpClient);
  private crypto = inject(CryptoService);

  private ws?: WebSocket;
  public connected$ = new BehaviorSubject<boolean>(false);
  public onlineUsers$ = new BehaviorSubject<UserSummary[]>([]);
  public allUsers$ = new BehaviorSubject<UserSummary[]>([]);
  public messages$ = new Subject<ChatItem>();

  public messageExpired$ = new Subject<string>();

  private me: { id: string; name: string } | null = null;

  private pendingByKeyId: Record<string, any[]> = {};

  private globalThread: ChatItem[] = [];
  private dmThreads = new Map<string, ChatItem[]>();

  private readonly STORAGE_GLOBAL = 'rc_thread_global';
  private readonly STORAGE_DM_INDEX = 'rc_dm_index';

  private readonly DEFAULT_TTL = 24 * 60 * 60;
  private readonly TTL_KEY = 'rc_default_ttl_sec';

  getTtlSeconds(): number {
    const raw = localStorage.getItem(this.TTL_KEY);
    const n = raw ? parseInt(raw, 10) : NaN;
    return Number.isFinite(n) && n > 0 ? n : this.DEFAULT_TTL;
  }
  setTtlSeconds(seconds: number) {
    const s = Math.max(60, Math.floor(seconds));
    localStorage.setItem(this.TTL_KEY, String(s));
  }

  setMe(user: { id: string; name: string } | null) {
    this.me = user;
    if (user) {

      this.hydrateFromStorage();
    } else {
      this.globalThread = [];
      this.dmThreads.clear();
    }
  }

  connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;
    const wsUrl = environment.apiUrl.replace('/api', '/ws').replace('http', 'ws');
    this.ws = new WebSocket(wsUrl);
    this.ws.onopen = () => this.connected$.next(true);
    this.ws.onclose = () => {
      this.connected$.next(false);
      setTimeout(() => this.connect(), 1500);
    };
    this.ws.onmessage = (ev) => this.handleIncoming(ev.data);
  }

  async loadAllUsers() {
    const list = await this.http.get<any[]>(`${environment.apiUrl}/users`, { withCredentials: true }).toPromise();
    const users = (list || []).map(u => ({ id: u.id, name: u.name })) as UserSummary[];

    const meId = this.me?.id;
    this.allUsers$.next(users.filter(u => u.id !== meId));
  }

  private sendRaw(obj: any) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    this.ws.send(JSON.stringify(obj));
  }

  async sendDirect(toUser: UserSummary, plaintext: string) {
    if (!this.me) return;
    let dm = this.crypto.getDmKey(toUser.id);
    if (!dm) {
      const keyRawB64 = await this.crypto.generateAesKeyRawB64();
      const keyId = crypto.randomUUID();

      const keys: any[] = await this.http
        .post(`${environment.apiUrl}/public-keys`, [toUser.id], { withCredentials: true })
        .toPromise() as any[];
      const pub = keys.find((k: any) => k.user_id === toUser.id)?.public_key;
      if (!pub) throw new Error('Recipient has no public key');
      const encKeyB64 = await this.crypto.encryptForPublicKey(pub, this.strToBuf(keyRawB64));

      this.sendRaw({
        type: 'KeyExchange',
        from_user_id: this.me.id,
        to_user_id: toUser.id,
        encrypted_key: encKeyB64,
        key_id: keyId,
        scope: 'dm',
      });
      this.crypto.setDmKey(toUser.id, keyRawB64, keyId);
      dm = { key: keyRawB64, keyId };
    }

    try {
      const keys2: any[] = await this.http
        .post(`${environment.apiUrl}/public-keys`, [toUser.id], { withCredentials: true })
        .toPromise() as any[];
      const pub2 = keys2.find((k: any) => k.user_id === toUser.id)?.public_key;
      if (pub2) {
        const encKeyB64b = await this.crypto.encryptForPublicKey(pub2, this.strToBuf(dm.key));
        this.sendRaw({ type: 'KeyExchange', from_user_id: this.me.id, to_user_id: toUser.id, encrypted_key: encKeyB64b, key_id: dm.keyId, scope: 'dm' });
      }
    } catch {}

    const { contentB64, ivB64 } = await this.crypto.encryptWithAesRawB64(dm.key, plaintext);
    const messageId = crypto.randomUUID();
    const ttl = this.getTtlSeconds();
    this.sendRaw({
      type: 'EncryptedMessage',
      sender_id: this.me.id,
      sender_username: this.me.name,
      encrypted_content: JSON.stringify({ content: contentB64, iv: ivB64, key_id: dm.keyId }),
      recipients: [toUser.id],
      timestamp: new Date().toISOString(),
      message_id: messageId,
      room: 'dm',
      ttl_seconds: ttl,
    });

    const item: ChatItem = { id: messageId, fromId: this.me.id, fromName: this.me.name, toIds: [toUser.id], room: 'dm', text: plaintext, at: new Date().toISOString() };
    this.ensureDmThread(toUser.id).push(item);
    this.persistDmThread(toUser.id);
    this.messages$.next(item);
    this.scheduleExpiry(item, ttl);
  }

  async sendGlobal(plaintext: string) {
    if (!this.me) return;

    let g = this.crypto.getGlobalKey();
    const online = this.onlineUsers$.value.filter(u => u.id !== this.me!.id);
    if (!g) {
      const key = await this.crypto.generateAesKeyRawB64();
      const keyId = crypto.randomUUID();

      for (const u of online) {
        try {
          const keys: any[] = await this.http
            .post(`${environment.apiUrl}/public-keys`, [u.id], { withCredentials: true })
            .toPromise() as any[];
          const pub = keys.find((k: any) => k.user_id === u.id)?.public_key;
          if (!pub) continue;
          const encKeyB64 = await this.crypto.encryptForPublicKey(pub, this.strToBuf(key));
          this.sendRaw({ type: 'KeyExchange', from_user_id: this.me.id, to_user_id: u.id, encrypted_key: encKeyB64, key_id: keyId, scope: 'global' });
        } catch {}
      }
      this.crypto.setGlobalKey(key, keyId);
      g = { key, keyId };
    }

    const { contentB64, ivB64 } = await this.crypto.encryptWithAesRawB64(g.key, plaintext);
    const messageId = crypto.randomUUID();
    const recipients = online.map(u => u.id);
    const ttl = this.getTtlSeconds();
    this.sendRaw({
      type: 'EncryptedMessage',
      sender_id: this.me.id,
      sender_username: this.me.name,
      encrypted_content: JSON.stringify({ content: contentB64, iv: ivB64, key_id: g.keyId }),
      recipients,
      timestamp: new Date().toISOString(),
      message_id: messageId,
      room: 'global',
      ttl_seconds: ttl,
    });
    const item: ChatItem = { id: messageId, fromId: this.me.id, fromName: this.me.name, toIds: recipients, room: 'global', text: plaintext, at: new Date().toISOString() };
    this.globalThread.push(item);
    this.persistGlobalThread();
    this.messages$.next(item);
    this.scheduleExpiry(item, ttl);
  }

  private async handleIncoming(raw: string) {
    try {
      const msg = JSON.parse(raw);
      switch (msg.type) {
        case 'OnlineUsers': {
          // initial presence sync
          const users = (msg.users || []).map((u: any) => ({ id: u.user_id, name: u.username }));
          // filter out self if known
          const meId = this.me?.id;
          const filtered = users.filter((u: any) => u.id !== meId);
          this.onlineUsers$.next(filtered);
          // If we already have a global key, proactively share it with everyone listed
          const g = this.crypto.getGlobalKey();
          const myId = this.me?.id;
          if (g && myId) {
            filtered.forEach(async (u: any) => {
              try {
                const keys: any[] = await this.http
                  .post(`${environment.apiUrl}/public-keys`, [u.id], { withCredentials: true })
                  .toPromise() as any[];
                const pub = keys.find((k: any) => k.user_id === u.id)?.public_key;
                if (!pub) return;
                const encKeyB64 = await this.crypto.encryptForPublicKey(pub, this.strToBuf(g.key));
                this.sendRaw({ type: 'KeyExchange', from_user_id: myId, to_user_id: u.id, encrypted_key: encKeyB64, key_id: g.keyId, scope: 'global' });
              } catch {}
            });
          }
          break;
        }
        case 'UserJoined':
          this.addOnline({ id: msg.user_id, name: msg.username });
          // share global key with new user if we have one
          if (this.me && msg.user_id !== this.me.id) {
            const g = this.crypto.getGlobalKey();
            if (g) {
              try {
                // fetch public key and send KeyExchange
                const keys: any[] = await this.http.post(`${environment.apiUrl}/public-keys`, [msg.user_id], { withCredentials: true }).toPromise() as any[];
                const pub = keys.find((k: any) => k.user_id === msg.user_id)?.public_key;
                if (pub) {
                  const encKeyB64 = await this.crypto.encryptForPublicKey(pub, this.strToBuf(g.key));
                  this.sendRaw({ type: 'KeyExchange', from_user_id: this.me.id, to_user_id: msg.user_id, encrypted_key: encKeyB64, key_id: g.keyId, scope: 'global' });
                }
              } catch {}
            }
          }
          break;
        case 'UserLeft':
          this.removeOnline(msg.user_id);
          break;
        case 'KeyExchange':
          console.debug('[WS] KeyExchange', msg);
          if (this.me && msg.to_user_id === this.me.id) {
            const rawBuf = await this.crypto.decryptWithPrivateKey(msg.encrypted_key);
            const rawB64 = new TextDecoder().decode(rawBuf);
            // Explicitly store by scope
            if (msg.scope === 'global') {
              // Add historical global key (do not switch current unless this is the key we use now)
              this.crypto.addGlobalKey(rawB64, msg.key_id);
            } else {
              // default to DM if not specified
              this.crypto.setDmKey(msg.from_user_id, rawB64, msg.key_id);
            }
            // Process any pending messages that reference this key
            await this.processPendingForKey(msg.key_id);
          }
          break;
        case 'EncryptedMessage': {
          // decrypt based on key_id
          console.debug('[WS] EncryptedMessage', raw);
          const { content, iv, key_id } = JSON.parse(msg.encrypted_content || '{}');
          if (!this.me) return;
          // Use explicit room when provided
          const isGlobal = msg.room === 'global';
          const ttlSec = typeof msg.ttl_seconds === 'number' ? Math.max(0, Math.floor(msg.ttl_seconds)) : this.DEFAULT_TTL;
          let keyRec: { key: string; keyId: string } | null = null;
          if (isGlobal) keyRec = this.crypto.getGlobalKeyById(key_id) || this.crypto.getGlobalKey();
          else keyRec = this.crypto.getDmKeyById(msg.sender_id, key_id) || this.crypto.getDmKey(msg.sender_id);
          if (!keyRec) {
            if (!this.pendingByKeyId[key_id]) this.pendingByKeyId[key_id] = [];
            this.pendingByKeyId[key_id].push(msg);
            break;
          }
          await this.tryDecryptAndEmit(msg, keyRec.key, isGlobal, ttlSec);
          break;
        }
        case 'PublicKeysResponse':
        case 'SystemMessage':
        default:
          break;
      }
    } catch (e) { console.warn('WS parse/decrypt error', e); }
  }

  private async processPendingForKey(keyId: string) {
    const list = this.pendingByKeyId[keyId];
    if (!list || !list.length) return;
    const pending = list.splice(0, list.length);
    const g = this.crypto.getGlobalKeyById(keyId) || this.crypto.getGlobalKey();
    const globalKey = g && g.keyId === keyId ? g.key : null;
    for (const m of pending) {
      const ttlSec = typeof m.ttl_seconds === 'number' ? Math.max(0, Math.floor(m.ttl_seconds)) : this.DEFAULT_TTL;
      if (globalKey) {
        await this.tryDecryptAndEmit(m, globalKey, true, ttlSec);
        continue;
      }
      const dm = this.crypto.getDmKeyById(m.sender_id, keyId) || this.crypto.getDmKey(m.sender_id);
      if (dm && dm.keyId === keyId) {
        await this.tryDecryptAndEmit(m, dm.key, false, ttlSec);
      } else {
        // still missing; requeue
        if (!this.pendingByKeyId[keyId]) this.pendingByKeyId[keyId] = [];
        this.pendingByKeyId[keyId].push(m);
      }
    }
  }

  private async tryDecryptAndEmit(msg: any, keyRawB64: string, isGlobal: boolean, ttlSec?: number) {
    try {
      const payload = JSON.parse(msg.encrypted_content || '{}');
      const text = await this.crypto.decryptWithAesRawB64(keyRawB64, payload.content, payload.iv);
      const item: ChatItem = {
        id: msg.message_id,
        fromId: msg.sender_id,
        fromName: msg.sender_username,
        toIds: msg.recipients || [],
        room: isGlobal ? 'global' : 'dm',
        text,
        at: msg.timestamp,
      };
      // Store
      if (isGlobal) {
        if (!this.globalThread.find(x => x.id === item.id)) {
          this.globalThread.push(item);
          this.persistGlobalThread();
        }
      } else if (this.me) {
        const peerId = item.fromId === this.me.id ? (item.toIds[0] || '') : item.fromId;
        if (peerId) {
          const list = this.ensureDmThread(peerId);
          if (!list.find(x => x.id === item.id)) {
            list.push(item);
            this.persistDmThread(peerId);
          }
        }
      }
      this.messages$.next(item);
      this.scheduleExpiry(item, typeof ttlSec === 'number' ? ttlSec : this.DEFAULT_TTL);
    } catch (e) { console.warn('Decrypt failed', e, msg); }
  }

  private ensureDmThread(userId: string): ChatItem[] {
    let list = this.dmThreads.get(userId);
    if (!list) { list = []; this.dmThreads.set(userId, list); }
    return list;
  }

  getGlobalThread(): ChatItem[] { return this.globalThread; }
  getDmThread(userId: string): ChatItem[] { return this.ensureDmThread(userId); }

  private scheduleExpiry(item: ChatItem, ttlSeconds: number) {
    const delay = Math.max(0, ttlSeconds) * 1000;
    window.setTimeout(() => {
      if (item.room === 'global') {
        this.globalThread = this.globalThread.filter(m => m.id !== item.id);
        this.persistGlobalThread();
      } else if (this.me) {
        const peerId = item.fromId === this.me.id ? (item.toIds[0] || '') : item.fromId;
        if (peerId) {
          const list = this.ensureDmThread(peerId);
          const idx = list.findIndex(m => m.id === item.id);
          if (idx >= 0) list.splice(idx, 1);
          this.persistDmThread(peerId);
        }
      }
      this.messageExpired$.next(item.id);
    }, delay);
  }

  private addOnline(u: UserSummary) {
    if (this.me && u.id === this.me.id) return;
    const exists = this.onlineUsers$.value.some(x => x.id === u.id);
    if (!exists) this.onlineUsers$.next([...this.onlineUsers$.value, u]);
  }
  private removeOnline(userId: string) {
    this.onlineUsers$.next(this.onlineUsers$.value.filter(u => u.id !== userId));
  }

  private strToBuf(s: string): ArrayBuffer {
    return new TextEncoder().encode(s).buffer;
  }

  // Persistence helpers
  private hydrateFromStorage() {
    try {
      // Global
      const gRaw = localStorage.getItem(this.STORAGE_GLOBAL);
      if (gRaw) {
        const items: ChatItem[] = JSON.parse(gRaw) || [];
        this.globalThread = this.filterExpired(items);
      }
      // DMs
      const idxRaw = localStorage.getItem(this.STORAGE_DM_INDEX);
      const ids: string[] = idxRaw ? JSON.parse(idxRaw) : [];
      ids.forEach(id => {
        try {
          const raw = localStorage.getItem(this.dmStorageKey(id));
          if (raw) {
            const items: ChatItem[] = JSON.parse(raw) || [];
            this.dmThreads.set(id, this.filterExpired(items));
          }
        } catch {}
      });
    } catch {}
  }

  private filterExpired(items: ChatItem[]): ChatItem[] {
    const now = Date.now();
    const ttlMs = this.getTtlSeconds() * 1000;
    return (items || []).filter(it => {
      const at = Date.parse(it.at);
      return isFinite(at) ? now - at < ttlMs : true;
    });
  }

  private persistGlobalThread() {
    try {
      localStorage.setItem(this.STORAGE_GLOBAL, JSON.stringify(this.globalThread));
    } catch {}
  }
  private persistDmThread(peerId: string) {
    try {
      // Update index
      const idxRaw = localStorage.getItem(this.STORAGE_DM_INDEX);
      const idx: string[] = idxRaw ? JSON.parse(idxRaw) : [];
      if (!idx.includes(peerId)) {
        idx.push(peerId);
        localStorage.setItem(this.STORAGE_DM_INDEX, JSON.stringify(idx));
      }
      localStorage.setItem(this.dmStorageKey(peerId), JSON.stringify(this.ensureDmThread(peerId)));
    } catch {}
  }
  private dmStorageKey(peerId: string) { return `rc_thread_dm_${peerId}`; }
}
