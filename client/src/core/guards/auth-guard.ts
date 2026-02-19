import { CanActivateFn } from '@angular/router';
import { ToastService } from '../services/toast-service';
import { inject } from '@angular/core/primitives/di';
import { AccountService } from '../services/account-service';

export const authGuard: CanActivateFn = (route, state) => {
  const accountService = inject(AccountService);
  const toast = inject(ToastService);
  if (accountService.currentUser()) {
    return true;
  } else {
    toast.error('You shall not pass!');
    return false;
  }
};
