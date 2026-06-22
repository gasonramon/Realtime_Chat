import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class CryptoService {
  private http = inject(HttpClient);

  private readonly PUB_KEY_KEY = 'rc_pubkey_spki_b64';
  private readonly PRIV_KEY_KEY = 'rc_privkey_pkcs8_b64';
  private readonly GLOBAL_KEY = 'rc_global_aes_gcm_b64';
  private readonly GLOBAL_KEY_ID = 'rc_global_key_id';
  private readonly GLOBAL_KEYS_MAP = 'rc_global_keys_map';

  // Utility: base64 encoding/decoding (robust to PEM, URL-safe, and padding)
  private b64encode(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);

    if (typeof btoa === 'function') return btoa(binary);

    const g: any = globalThis as any;
    if (g?.Buffer) return g.Buffer.from(bytes).toString('base64');
    throw new Error('Base64 encode not supported in this environment');
  }
  private normalizeB64(input: string): string {
    if (!input) return '';

    const cleaned = input
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '')
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    // Fix padding
    const pad = cleaned.length % 4;
    return pad ? cleaned + '='.repeat(4 - pad) : cleaned;
  }
  private b64decode(b64: string): ArrayBuffer {
    const normalized = this.normalizeB64(b64);
    if (!normalized) return new ArrayBuffer(0);
    try {
      if (typeof atob === 'function') {
        const binary = atob(normalized);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const g: any = globalThis as any;
      if (g?.Buffer) {
        const buf = g.Buffer.from(normalized, 'base64');
        const out = new Uint8Array(buf.length);
        for (let i = 0; i < buf.length; i++) out[i] = buf[i];
        return out.buffer;
      }
    } catch {}
    throw new Error('Invalid base64 input');
  }

  async ensureKeyPair(): Promise<void> {
    const existing = localStorage.getItem(this.PUB_KEY_KEY);
    if (existing) return;

    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
    const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    localStorage.setItem(this.PUB_KEY_KEY, this.b64encode(spki));
    localStorage.setItem(this.PRIV_KEY_KEY, this.b64encode(pkcs8));
  }

  getPublicKeyString(): string | null {
    return localStorage.getItem(this.PUB_KEY_KEY);
  }

  private async importPublicKey(spkiB64: string): Promise<CryptoKey> {
    // Accept raw base64 or PEM format
    const spki = this.b64decode(spkiB64);
    return crypto.subtle.importKey(
      'spki',
      spki,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
  }

  private async importPrivateKey(): Promise<CryptoKey> {
    const pkcs8B64 = localStorage.getItem(this.PRIV_KEY_KEY);
    if (!pkcs8B64) throw new Error('Private key missing');
    const pkcs8 = this.b64decode(pkcs8B64);
    return crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt']
    );
  }

  async encryptForPublicKey(spkiB64: string, data: ArrayBuffer): Promise<string> {
    const pub = await this.importPublicKey(spkiB64);
    const enc = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, data);
    return this.b64encode(enc);
  }

  async decryptWithPrivateKey(dataB64: string): Promise<ArrayBuffer> {
    const priv = await this.importPrivateKey();
    const data = this.b64decode(dataB64);
    return crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, data);
  }

  async generateAesKeyRawB64(): Promise<string> {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const raw = await crypto.subtle.exportKey('raw', key);
    return this.b64encode(raw);
  }

  async encryptWithAesRawB64(keyRawB64: string, plaintext: string): Promise<{ contentB64: string; ivB64: string }>
  {
    const keyRaw = this.b64decode(keyRawB64);
    const key = await crypto.subtle.importKey('raw', keyRaw, { name: 'AES-GCM' }, false, ['encrypt']);
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return { contentB64: this.b64encode(ct), ivB64: this.b64encode(iv.buffer) };
  }

  async decryptWithAesRawB64(keyRawB64: string, contentB64: string, ivB64: string): Promise<string> {
    const keyRaw = this.b64decode(keyRawB64);
    const key = await crypto.subtle.importKey('raw', keyRaw, { name: 'AES-GCM' }, false, ['decrypt']);
    const ivBuf = this.b64decode(ivB64);
    const iv = new Uint8Array(ivBuf);
    if (iv.length !== 12) {
      throw new Error(`Invalid IV length: ${iv.length}`);
    }
    const contentBuf = this.b64decode(contentB64);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, contentBuf);
    return new TextDecoder().decode(pt);
  }

  // Global room key helpers
  getGlobalKey(): { key: string; keyId: string } | null {
    const key = localStorage.getItem(this.GLOBAL_KEY);
    const keyId = localStorage.getItem(this.GLOBAL_KEY_ID);
    if (key && keyId) return { key, keyId };
    return null;
  }
  setGlobalKey(key: string, keyId: string) {
    localStorage.setItem(this.GLOBAL_KEY, key);
    localStorage.setItem(this.GLOBAL_KEY_ID, keyId);
    // also store in map for historical decryption
    const map = this.getGlobalKeysMap();
    map[keyId] = key;
    localStorage.setItem(this.GLOBAL_KEYS_MAP, JSON.stringify(map));
  }
  addGlobalKey(key: string, keyId: string) {
    const map = this.getGlobalKeysMap();
    map[keyId] = key;
    localStorage.setItem(this.GLOBAL_KEYS_MAP, JSON.stringify(map));
  }
  getGlobalKeyById(keyId: string): { key: string; keyId: string } | null {
    const map = this.getGlobalKeysMap();
    const key = map[keyId];
    return key ? { key, keyId } : null;
  }
  private getGlobalKeysMap(): Record<string, string> {
    try {
      return JSON.parse(localStorage.getItem(this.GLOBAL_KEYS_MAP) || '{}');
    } catch {
      return {};
    }
  }

  // DM key helpers
  getDmKey(userId: string): { key: string; keyId: string } | null {
    const key = localStorage.getItem(`rc_dm_key_${userId}`);
    const keyId = localStorage.getItem(`rc_dm_key_id_${userId}`);
    if (key && keyId) return { key, keyId };
    return null;
  }
  getDmKeyById(userId: string, keyId: string): { key: string; keyId: string } | null {
    const map = this.getDmKeysMap(userId);
    const key = map[keyId];
    return key ? { key, keyId } : null;
  }
  setDmKey(userId: string, key: string, keyId: string) {
    localStorage.setItem(`rc_dm_key_${userId}`, key);
    localStorage.setItem(`rc_dm_key_id_${userId}`, keyId);
    const map = this.getDmKeysMap(userId);
    map[keyId] = key;
    localStorage.setItem(`rc_dm_keys_map_${userId}`, JSON.stringify(map));
  }
  private getDmKeysMap(userId: string): Record<string, string> {
    try {
      return JSON.parse(localStorage.getItem(`rc_dm_keys_map_${userId}`) || '{}');
    } catch {
      return {};
    }
  }
}
