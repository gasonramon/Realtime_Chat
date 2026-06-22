import { Component, inject } from '@angular/core';
import { AsyncPipe, NgIf } from '@angular/common';
import { AuthService } from '../../services/auth.service';
import { FormsModule } from '@angular/forms';
import { ChatService } from '../../services/chat.service';

@Component({
  selector: 'app-account',
  standalone: true,
  imports: [NgIf, AsyncPipe, FormsModule],
  templateUrl: './account.component.html',
  styleUrls: ['./account.component.scss'],
})
export class AccountComponent {
  public auth = inject(AuthService);
  private chat = inject(ChatService);
  ttl = this.chat.getTtlSeconds();

  saveTtl() {
    this.chat.setTtlSeconds(Number(this.ttl));
    this.ttl = this.chat.getTtlSeconds();

    this.auth.updateSettings({ default_ttl_seconds: this.ttl }).subscribe({
      next: () => {},
      error: () => {},
    });
  }

  constructor() {

    this.auth.getSettings().subscribe({
      next: (s: any) => {
        if (s && typeof s.default_ttl_seconds === 'number') {
          this.ttl = s.default_ttl_seconds;
          this.chat.setTtlSeconds(this.ttl);
        }
      },
    });
  }
}
