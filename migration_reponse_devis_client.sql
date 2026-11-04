-- PIXELLOCAL — Autoriser les clients à accepter/refuser les devis envoyés. À exécuter une seule fois.

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
