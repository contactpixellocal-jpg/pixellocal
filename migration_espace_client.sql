-- PIXELLOCAL — Migration espace client V5
-- À exécuter UNE SEULE FOIS dans Supabase > SQL Editor > New query.
-- Ne désactive pas RLS. Aucun mot de passe ni clé secrète n'est nécessaire.

-- 1) Autoriser les rôles administrateur et client.
alter table public.profils drop constraint if exists profils_role_check;
alter table public.profils add constraint profils_role_check check (role in ('admin','client'));

-- 2) Lier un compte Auth à une fiche client.
alter table public.clients add column if not exists user_id uuid unique references auth.users(id) on delete set null;

-- 3) Fonctions de contrôle exécutées avec les droits du propriétaire, pour éviter les boucles RLS.
create or replace function public.est_admin()
returns boolean language sql stable security definer set search_path = public, auth
as $$ select exists (select 1 from public.profils where id = auth.uid() and role = 'admin'); $$;

create or replace function public.mon_client_id()
returns uuid language sql stable security definer set search_path = public, auth
as $$ select id from public.clients where user_id = auth.uid() limit 1; $$;

revoke all on function public.est_admin() from public;
revoke all on function public.mon_client_id() from public;
grant execute on function public.est_admin() to authenticated;
grant execute on function public.mon_client_id() to authenticated;

-- 4) S'assurer que RLS reste activé.
alter table public.profils enable row level security;
alter table public.clients enable row level security;
alter table public.demandes enable row level security;
alter table public.devis enable row level security;
alter table public.rendez_vous enable row level security;
alter table public.paiements enable row level security;

-- 5) Profils : chaque utilisateur lit son profil ; l'administrateur gère tous les profils.
drop policy if exists "profil_lire_soi" on public.profils;
drop policy if exists "admin_profils" on public.profils;
create policy "profil_lire_soi" on public.profils for select to authenticated using (id = auth.uid());
create policy "admin_profils" on public.profils for all to authenticated using (public.est_admin()) with check (public.est_admin());

-- 6) Clients : administrateur complet, client lecture de sa seule fiche.
drop policy if exists "admin_clients" on public.clients;
create policy "admin_clients" on public.clients for all to authenticated using (public.est_admin()) with check (public.est_admin());
drop policy if exists "client_lire_sa_fiche" on public.clients;
create policy "client_lire_sa_fiche" on public.clients for select to authenticated using (user_id = auth.uid());

-- 7) Tables métier : administrateur complet ; client lecture de ses seules lignes.
drop policy if exists "admin_demandes" on public.demandes;
create policy "admin_demandes" on public.demandes for all to authenticated using (public.est_admin()) with check (public.est_admin());
drop policy if exists "client_lire_ses_demandes" on public.demandes;
create policy "client_lire_ses_demandes" on public.demandes for select to authenticated using (client_id = public.mon_client_id());

drop policy if exists "admin_devis" on public.devis;
create policy "admin_devis" on public.devis for all to authenticated using (public.est_admin()) with check (public.est_admin());
drop policy if exists "client_lire_ses_devis" on public.devis;
create policy "client_lire_ses_devis" on public.devis for select to authenticated using (client_id = public.mon_client_id());

drop policy if exists "admin_rendez_vous" on public.rendez_vous;
create policy "admin_rendez_vous" on public.rendez_vous for all to authenticated using (public.est_admin()) with check (public.est_admin());
drop policy if exists "client_lire_ses_rendez_vous" on public.rendez_vous;
create policy "client_lire_ses_rendez_vous" on public.rendez_vous for select to authenticated using (client_id = public.mon_client_id());

drop policy if exists "admin_paiements" on public.paiements;
create policy "admin_paiements" on public.paiements for all to authenticated using (public.est_admin()) with check (public.est_admin());
drop policy if exists "client_lire_ses_paiements" on public.paiements;
create policy "client_lire_ses_paiements" on public.paiements for select to authenticated using (client_id = public.mon_client_id());

-- 8) Formulaire public : conserver uniquement la création de demandes.
drop policy if exists "public_creer_demande" on public.demandes;
create policy "public_creer_demande" on public.demandes for insert to anon, authenticated
with check (length(trim(nom)) between 1 and 120 and length(trim(email)) between 3 and 254);

-- IMPORTANT : créer chaque compte client dans Supabase Auth, puis relier son UUID
-- à clients.user_id et créer son profil avec role='client'. Ne jamais mettre
-- la clé service_role dans un fichier HTML. L'invitation automatique par e-mail
-- nécessite une fonction serveur sécurisée et n'est pas activée par cette migration.


-- 9) Permettre au client de répondre à un devis envoyé, sans modifier son montant.
drop policy if exists "client_repondre_devis_envoye" on public.devis;
create policy "client_repondre_devis_envoye" on public.devis
for update to authenticated
using (client_id = public.mon_client_id() and statut = 'envoye')
with check (client_id = public.mon_client_id() and statut in ('accepte','refuse'));

create or replace function public.proteger_reponse_devis_client()
returns trigger language plpgsql security invoker set search_path = public, auth
as $$
begin
  if auth.uid() is not null and not public.est_admin() then
    if old.client_id is distinct from new.client_id
       or old.numero is distinct from new.numero
       or old.demande_id is distinct from new.demande_id
       or old.titre is distinct from new.titre
       or old.description is distinct from new.description
       or old.montant_ht is distinct from new.montant_ht
       or old.tva is distinct from new.tva
       or old.montant_ttc is distinct from new.montant_ttc
       or old.date_emission is distinct from new.date_emission
       or old.date_validite is distinct from new.date_validite
       or old.created_at is distinct from new.created_at
       or old.statut <> 'envoye'
       or new.statut not in ('accepte','refuse') then
      raise exception 'Le client peut uniquement accepter ou refuser un devis envoyé.';
    end if;
  end if;
  return new;
end;
$$;
drop trigger if exists proteger_reponse_devis_client on public.devis;
create trigger proteger_reponse_devis_client
before update on public.devis
for each row execute function public.proteger_reponse_devis_client();
