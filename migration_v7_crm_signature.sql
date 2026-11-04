-- PixelLocal V7 : statut devis dans l'administration + signature électronique client
-- À exécuter dans Supabase > SQL Editor. Compatible avec la migration V6 déjà appliquée.

ALTER TABLE public.devis
  ADD COLUMN IF NOT EXISTS signature_data text,
  ADD COLUMN IF NOT EXISTS signature_name text,
  ADD COLUMN IF NOT EXISTS signed_at timestamptz;

-- Les clients peuvent uniquement passer un devis envoyé à accepté/refusé.
DROP POLICY IF EXISTS "client_repondre_devis_envoye" ON public.devis;
CREATE POLICY "client_repondre_devis_envoye"
ON public.devis FOR UPDATE TO authenticated
USING (client_id = public.mon_client_id() AND statut = 'envoye')
WITH CHECK (client_id = public.mon_client_id() AND statut IN ('accepte','refuse'));

-- Le client ne peut changer ni le prix ni le contenu : uniquement son choix
-- et, en cas d'acceptation, les éléments de signature.
CREATE OR REPLACE FUNCTION public.proteger_reponse_devis_client()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path = public, auth
AS $$
BEGIN
  IF auth.uid() IS NOT NULL AND NOT public.est_admin() THEN
    IF OLD.client_id IS DISTINCT FROM NEW.client_id
       OR OLD.numero IS DISTINCT FROM NEW.numero
       OR OLD.demande_id IS DISTINCT FROM NEW.demande_id
       OR OLD.titre IS DISTINCT FROM NEW.titre
       OR OLD.description IS DISTINCT FROM NEW.description
       OR OLD.montant_ht IS DISTINCT FROM NEW.montant_ht
       OR OLD.tva IS DISTINCT FROM NEW.tva
       OR OLD.montant_ttc IS DISTINCT FROM NEW.montant_ttc
       OR OLD.date_emission IS DISTINCT FROM NEW.date_emission
       OR OLD.date_validite IS DISTINCT FROM NEW.date_validite
       OR OLD.created_at IS DISTINCT FROM NEW.created_at
       OR OLD.statut <> 'envoye'
       OR NEW.statut NOT IN ('accepte','refuse') THEN
      RAISE EXCEPTION 'Le client peut uniquement répondre à un devis envoyé.';
    END IF;
    IF NEW.statut = 'accepte' THEN
      IF NEW.signature_data IS NULL OR length(NEW.signature_data) > 1000000
         OR NEW.signature_name IS NULL OR length(trim(NEW.signature_name)) < 2
         OR NEW.signed_at IS NULL THEN
        RAISE EXCEPTION 'Une signature et le nom du signataire sont obligatoires pour accepter.';
      END IF;
    ELSE
      NEW.signature_data := NULL;
      NEW.signature_name := NULL;
      NEW.signed_at := NULL;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS proteger_reponse_devis_client ON public.devis;
CREATE TRIGGER proteger_reponse_devis_client
BEFORE UPDATE ON public.devis
FOR EACH ROW EXECUTE FUNCTION public.proteger_reponse_devis_client();

-- Le rôle admin conserve son accès complet via la politique admin_devis existante.
