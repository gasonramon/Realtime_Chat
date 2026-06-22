import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { catchError, map, of } from 'rxjs';

export const requireAuthGuard: CanActivateFn = (_route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (auth.user$.value) return true;


  return auth.me().pipe(
    map(() => {
      return auth.user$.value
        ? true
        : router.createUrlTree(['/login'], { queryParams: { redirect: state.url } });
    }),
    catchError(() => of(router.createUrlTree(['/login'], { queryParams: { redirect: state.url } })))
  );
};

