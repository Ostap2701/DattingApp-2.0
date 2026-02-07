export type User = {
  id: number;
  username: string;
  token: string;
  displayName: string;
  imageUrl?: string;
};

export type LoginCreds = {
  username: string;
  password: string;
};

export type RegisterCreds = {
  email: string;
  password: string;
  displayName: string;
};