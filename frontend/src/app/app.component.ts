import { routes } from './app.routes';
import { Component, inject } from '@angular/core';
import { NgModel } from '@angular/forms';
import { RouterOutlet, RouterLink, Router } from '@angular/router';
import { NgIf, AsyncPipe } from '@angular/common';
import { AuthService } from './services/auth.service';
import { RegisterComponent } from './components/register/register.component';
import { LoginComponent } from './components/login/login.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, NgIf, AsyncPipe],
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss'
})
export class AppComponent {
  title = 'realtime_chat_frontend';
  routes = routes;
  RouterLink = RouterLink;
  public auth = inject(AuthService);
  private router = inject(Router);

  onLogout() {
    this.auth.logout().subscribe({
      next: () => this.router.navigate(['/login']),
      error: () => this.router.navigate(['/login'])
    });
  }
}
