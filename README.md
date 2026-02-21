# Abboya Backend MVP (Code)

Implémentation **code** d’un noyau SaaS de réservation pour PME africaines (WhatsApp-first, anti no-show, paiements traçables, sécurité des données).

## Ce qui est implémenté

- Gestion multi-business (PME) avec lien de réservation (`booking_slug`).
- Comptes `owner`, `staff`, `customer` avec règles RBAC.
- Services configurables (durée/prix/acompte).
- Réservation, annulation, report.
- Prévention de double réservation (intégrité agenda).
- Rappels automatiques (sélection des RDV à rappeler).
- Statistiques simples par business.
- Authentification sécurisée :
  - hash mot de passe `PBKDF2-SHA256`
  - tokens signés `HMAC-SHA256` (expirables)
- Protection données clients :
  - minimisation (pas de stockage phone en clair)
  - hash téléphone + masque `last4`
- Journal d’audit chaîné (hash chain) pour vérifier l’intégrité des opérations.

## Structure

- `abboya/models.py` : modèles métier.
- `abboya/security.py` : hash MDP, signature token, hash téléphone.
- `abboya/audit.py` : audit append-only + validation d’intégrité.
- `abboya/platform.py` : logique métier (réservation, permissions, stats).
- `main.py` : exemple d’utilisation.
- `tests/test_platform.py` : tests unitaires.

## Exécution

```bash
python3 main.py
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```
