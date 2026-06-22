import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { FormsModule } from '@angular/forms';
import { inject } from '@angular/core';
import { NgIf } from '@angular/common';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  standalone: true,
  imports: [FormsModule, RouterLink, NgIf],
  styleUrls: ['./login.component.scss'],
})
export class LoginComponent implements OnInit {
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private auth = inject(AuthService);
  username = '';
  password = '';
  otpCode = '';
  loading = false;
  error: string | null = null;
  info: string | null = null;
  twoFaRequired = false;
  tempSessionId: string | null = null;
  private redirectTo: string | null = null;

  ngOnInit(): void {
    this.route.queryParamMap.subscribe((p) => {
      if (p.get('registered')) {
        this.info = 'Account created. Please sign in to continue.';
      }
      this.redirectTo = p.get('redirect');
    });
  }

  submit() {
    this.error = null;
    this.loading = true;
    this.auth.login({ name: this.username, password: this.password }).subscribe({
      next: (res: any) => {
        this.loading = false;
        if (res?.requires_2fa && res?.temp_session_id) {
          this.twoFaRequired = true;
          this.tempSessionId = res.temp_session_id;
          this.info = 'We sent a 6-digit verification code to your email.';
        } else {
          this.error = res?.message ?? 'Login failed';
        }
      },
      error: (err) => {
        this.loading = false;
        this.error = err?.error?.message ?? 'Login failed';
      },
    });
  }

  verifyOtp() {
    if (!this.tempSessionId) return;
    this.error = null;
    this.loading = true;
    this.auth
      .verifyOtp({ otp_code: this.otpCode.trim(), temp_session_id: this.tempSessionId })
      .subscribe({
        next: () => {
          this.loading = false;
          const target = this.redirectTo || '/chat';
          this.router.navigate([target]);
        },
        error: (err) => {
          this.loading = false;
          this.error = err?.error?.message ?? 'Verification failed';
        },
      });
  }
}
