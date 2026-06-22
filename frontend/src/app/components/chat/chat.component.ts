import { Component, OnDestroy, OnInit, inject, ViewChild, ElementRef } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AsyncPipe, DatePipe, NgFor, NgIf } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ChatService, ChatItem, UserSummary } from '../../services/chat.service';

@Component({
  selector: 'app-chat',
  imports: [RouterLink, NgFor, NgIf, FormsModule, AsyncPipe, DatePipe],
  templateUrl: './chat.component.html',
  styleUrl: './chat.component.scss'
})
export class ChatComponent implements OnInit, OnDestroy {
  private chat = inject(ChatService);
  @ViewChild('messagesEl') messagesRef?: ElementRef<HTMLDivElement>;

  connected$ = this.chat.connected$;
  users$ = this.chat.onlineUsers$;
  directory$ = this.chat.allUsers$;
  messages: ChatItem[] = [];

  activeRoom: 'global' | 'dm' = 'global';
  activeUser: UserSummary | null = null;
  draft = '';
  query = '';

  private online: UserSummary[] = [];
  private allUsers: UserSummary[] = [];

  private sub?: any;

  ngOnInit() {
    // Load the full user directory for offline DMs
    this.chat.loadAllUsers();
    this.chat.onlineUsers$.subscribe(u => (this.online = u || []));
    this.chat.allUsers$.subscribe(u => (this.allUsers = u || []));
    this.sub = this.chat.messages$.subscribe((m) => {
      // Only show messages matching current room
      let added = false;
      if (this.activeRoom === 'global' && m.room === 'global') { this.messages.push(m); added = true; }
      if (this.activeRoom === 'dm' && m.room === 'dm' && this.activeUser && (m.fromId === this.activeUser.id || m.toIds.includes(this.activeUser.id))) { this.messages.push(m); added = true; }
      if (added) this.scrollToBottomSoon();
    });
    // Remove messages locally when TTL fires
    this.chat.messageExpired$.subscribe((id) => {
      const before = this.messages.length;
      this.messages = this.messages.filter(m => m.id !== id);
      if (this.messages.length !== before) {
        // trigger change detection by reassigning (already done)
      }
    });
    // Preload global thread on first load/refresh
    this.setGlobal();
  }

  ngOnDestroy() {
    this.sub?.unsubscribe?.();
  }

  setGlobal() {
    this.activeRoom = 'global';
    this.activeUser = null;
    this.messages = [...this.chat.getGlobalThread()];
    this.scrollToBottomSoon();
  }

  openDm(u: UserSummary) {
    this.activeRoom = 'dm';
    this.activeUser = u;
    this.messages = [...this.chat.getDmThread(u.id)];
    this.scrollToBottomSoon();
  }

  async send() {
    const text = this.draft.trim();
    if (!text) return;
    if (this.activeRoom === 'global') await this.chat.sendGlobal(text);
    else if (this.activeUser) await this.chat.sendDirect(this.activeUser, text);
    this.draft = '';
  }

  offlineUsers(): UserSummary[] {
    const offline = this.allUsers.filter(a => !this.online.find(o => o.id === a.id));
    if (!this.query) return offline;
    const q = this.query.toLowerCase();
    return offline.filter(u => u.name.toLowerCase().includes(q));
  }

  private scrollToBottomSoon() {
    // allow DOM to render
    setTimeout(() => this.scrollToBottom(), 0);
  }
  private scrollToBottom() {
    const el = this.messagesRef?.nativeElement;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }
}
