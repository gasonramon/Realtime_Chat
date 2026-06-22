
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, tap } from 'rxjs';
import { environment } from '../environments/environment';
import { CryptoService } from './crypto.service';
import { ChatService } from './chat.service';

export interface AuthResponse {
  success: boolean;
  message: string;
  user?: any;
  requires_2fa?: boolean;
  temp_session_id?: string;
}

export interface VerifyOtpPayload {
  otp_code: string;
  temp_session_id: string;
}

export interface SettingsResponse { default_ttl_seconds: number; }
export interface ForgotPasswordPayload { email: string }
export interface ResetPasswordPayload { token: string; new_password: string }

@Injectable({ providedIn: 'root' })
export class AuthService {
  private http = inject(HttpClient);
  private crypto = inject(CryptoService);
  private chat = inject(ChatService);
  public user$ = new BehaviorSubject<any>(null);


  register(payload: { name: string; email: string; password: string }) {
    return this.http
      .post<AuthResponse>(`${environment.apiUrl}/register`, payload, { withCredentials: true })
      .pipe(
        tap((res) => {
          // Backend returns created user but does not create a session
          this.user$.next(res?.user ?? null);
        })
      );
  }

  login(credentials: { name: string; password: string }) {
    return this.http.post<AuthResponse>(`${environment.apiUrl}/login`, credentials, {
      withCredentials: true,
    });
  }

  verifyOtp(payload: VerifyOtpPayload) {
    return this.http
      .post(`${environment.apiUrl}/2fa/verify`, payload, { withCredentials: true })
      .pipe(
        tap(() => {

          this.me().subscribe();
        })
      );
  }

  me() {
    return this.http
      .get(`${environment.apiUrl}/me`, { withCredentials: true })
      .pipe(
        tap(async (res: any) => {
          this.user$.next(res ?? null);
          if (res && res.id) {
            this.chat.setMe({ id: res.id, name: res.name });

            await this.crypto.ensureKeyPair();
            if (!res.public_key) {
              const pub = this.crypto.getPublicKeyString();
              if (pub) {
                await this.http
                  .post(`${environment.apiUrl}/update-public-key`, { public_key: pub }, { withCredentials: true })
                  .toPromise();
              }
            }
            this.chat.connect();
          }
        })
      );
  }

  logout() {
    return this.http.post(`${environment.apiUrl}/logout`, {}, { withCredentials: true }).pipe(
      tap(() => {
        this.user$.next(null);
      })
    );
  }

  getSettings() {
    return this.http.get<SettingsResponse>(`${environment.apiUrl}/settings`, { withCredentials: true });
  }
  updateSettings(payload: SettingsResponse) {
    return this.http.post<SettingsResponse>(`${environment.apiUrl}/settings`, payload, { withCredentials: true });
  }

  forgotPassword(payload: ForgotPasswordPayload) {
    return this.http.post(`${environment.apiUrl}/password/forgot`, payload, { withCredentials: true });
  }
}
