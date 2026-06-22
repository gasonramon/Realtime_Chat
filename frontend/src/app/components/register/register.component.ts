import { AuthService } from '../../services/auth.service';
import { Component } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { NgIf } from '@angular/common';
import { inject } from '@angular/core';
@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  standalone: true,
  imports: [FormsModule, RouterLink,NgIf],
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent {
  private auth =  inject(AuthService);
  private router = inject(Router);
  public username = '';
  public email = '';
  public password = '';
  public confirm = '';
  public loading = false;
  public error: string | null = null;
  

  submit() {
    this.error = null;
    if (!this.username || !this.password || !this.email) {
      this.error = 'Username,Email and password are required';
      return;
    }
    if (this.password !== this.confirm) {
      this.error = 'Passwords do not match';
      return;
    }

    this.loading = true;
    this.auth.register({ name: this.username, email: this.email, password: this.password }).subscribe({
      next: () => {
        this.loading = false;
        // After registering, direct users to login to complete 2FA
        this.router.navigate(['/login'], { queryParams: { registered: 1 } });
      },
      error: (err) => {
        this.loading = false;
        this.error = err?.error?.message ?? 'Registration failed';
      }
    });
  }
}
