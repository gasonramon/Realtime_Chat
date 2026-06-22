import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { NgIf } from '@angular/common';

@Component({
  selector: 'app-forgot-password',
  standalone: true,
  imports: [FormsModule, RouterLink, NgIf],
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.scss'],
})
export class ForgotPasswordComponent {
  private auth = inject(AuthService);
  email = '';
  loading = false;
  info: string | null = null;
  error: string | null = null;

  submit() {
    this.info = this.error = null;
    this.loading = true;
    this.auth.forgotPassword({ email: this.email }).subscribe({
      next: () => { this.loading = false; this.info = 'If the email exists, a reset link has been sent.'; },
      error: () => { this.loading = false; this.info = 'If the email exists, a reset link has been sent.'; }
    });
  }
}
