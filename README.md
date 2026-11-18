# Le relais · CM1

Espace de remplacement disponible sur https://munozmelanie.github.io/.

Le visiteur saisit le mot de passe indiqué sur le mémo de classe. Aucun compte n’est nécessaire. Le programme et les documents sont chiffrés avant leur publication ; le navigateur les déchiffre localement. Le mot de passe n’est pas envoyé à GitHub et n’est pas conservé dans ce dépôt.

Le dossier `public/` contient l’interface et les données chiffrées. GitHub Actions publie uniquement ce dossier. Les préparations originales, les dossiers de journée en clair et le mémo portant le mot de passe restent sur l’ordinateur de l’enseignante, hors du dépôt.

## Mise à jour

Les scripts `scripts/crypto-vault.py` et `scripts/publish-github.py` préparent et publient un lot de journée validé. Le mot de passe est lu dans le trousseau macOS (`relais-cm1-reader`, compte `munozmelanie.github.io`). Les autorisations Git passent par l’outil de gestion des identifiants déjà configuré.

```sh
python3 scripts/publish-github.py --bundle /chemin/vers/le/lot/YYYY-MM-DD
```

Le premier déploiement utilise `--prepare-only` avant la publication initiale du code. Les tâches ultérieures publient uniquement les fichiers chiffrés. Le script refuse les conflits Git ou les modifications de code non validées. Une publication Git réussie doit être suivie du contrôle du déploiement Pages et des téléchargements déchiffrés.

Les archives visibles sont limitées à quatorze jours. L’historique Git conserve les versions chiffrées précédentes ; surveiller la taille du dépôt au fil de l’année. Changer le mot de passe ne révoque pas les fichiers déjà téléchargés.

## Vérification

Les tests vérifient le chiffrement, le rejet d’un mauvais mot de passe ou d’un fichier altéré, la compatibilité Python/Web Crypto et la publication Git atomique. Les fonctionnalités du navigateur utilisent uniquement ses API standard, sans dépendance chargée depuis un site tiers.
