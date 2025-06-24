import re
import os
import unicodedata

KEYWORDS = [
    'cv', 'diplome', 'releve', 'contrat', 'facture', 'assurance', 'avis',
    'wifi', 'internet', 'electricite', 'eau', 'note', 'banque', 'cnss',
    'loyer', 'impot', 'consultation', 'analyse', 'scolarite', 'sante', 'transport'
]

def normalize(text):
    return ''.join(
        c for c in unicodedata.normalize('NFD', text)
        if unicodedata.category(c) != 'Mn'
    ).lower()

def extract_category_from_filename(filename):
    name = normalize(re.sub(r'[^a-zA-Z]', ' ', filename))
    words = name.split()
    for word in words:
        if word in KEYWORDS:
            return word.lower()
    return None

def guess_fallback_category(text):
    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if len(line) > 5 and not line.isdigit():
            guess = re.sub(r'[^a-zA-Z0-9àâçéèêëîïôûùüÿñæœ\' ]', '', line).strip()
            return guess.split()[0].lower()
    return 'autres'

def to_slug(s):
    s = s.lower()
    s = re.sub(r'[^a-z0-9]+', '_', s)
    s = s.strip('_')
    return s

def classify_document(text, filename=None, fallback_text=None):
    text = (text or '').lower()
    print(text)
    # 1. تصنيف من اسم الملف
    if filename:
        category_from_name = extract_category_from_filename(filename)
        if category_from_name:
            return category_from_name

    # 2. تصنيف من محتوى النص
    categories = {
        'eau': ['ramsa','Ramsa', 'ade', 'eau potable', 'm³', "facture d'eau", "distribution d'eau", 'consommation', 'police', 'compteur', 'regie autonome', 'onee'],
        'électricité': ['reda', 'lydec', 'électricité', 'kwh', 'puissance', 'compteur', 'voltage', 'branche electricité', 'onee', "facture d'électricité"],
        'internet': ['inwi', 'orange', 'iam', 'maroc telecom', 'adsl', 'fibre', 'modem', 'box', 'connexion', 'internet', 'facture internet'],
        'telephone': ['forfait mobile', 'recharge', 'appels', 'sms', 'telecom', 'inwi', 'orange', 'iam', 'mobile', 'numéro'],
        'assurance': ['assurance', 'contrat', 'prime', 'police', 'compagnie', 'sinistre', 'attestation', 'valable du'],
        'banque': ['relevé bancaire', 'virement', 'rib', 'solde', 'banque', 'bancaire', 'transaction', 'date opération', 'agence', 'retrait', 'guichet'],
        'impots': ['avis d\'imposition', 'taxe', 'impôt', 'impôts', 'tva', 'déclaration', 'patente', 'professionnelle', 'identifiant fiscal'],
        'loyer': ['quittance', 'loyer', 'location', 'bail', 'locataire', 'propriétaire', 'adresse', 'mois', 'montant'],
        'cnss': ['cnss', 'caisse nationale', 'sécurité sociale', 'immatriculation', 'cotisations', 'déclaration cnss', 'assurance maladie obligatoire', 'amo', 'numéro cnss', 'attestation cnss', 'cotisation cnss', 'relevé cnss'],
        'cv': ['cv', 'curriculum vitae', 'expérience', 'formation', 'compétences', 'références', 'contact', 'expériences professionnelles', 'profil', 'langues', 'objectif', 'professionnel'],
        'diplome': ['diplôme', 'attestation', 'certificat', 'université', 'formation', 'licence', 'baccalauréat', 'établissement', 'mention'],
        'scolarite': ['frais de scolarité', 'inscription', 'école', 'étudiant', 'scolarité', 'niveau', 'reçu', 'facture école', 'année scolaire'],
        'sante': ['clinique', 'consultation', 'analyse', 'laboratoire', 'facture', 'ordonnance', 'médecin', 'mutuelle', 'acte médical', 'rdv'],
        'transport': ['ctm', 'oncf', 'ticket', 'trajet', 'réservation', 'transfert', 'numéro de siège', 'transport', 'prix', 'bus', 'train']
    }

    max_score = 0
    best_match = None
    for cat, keywords in categories.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > max_score:
            max_score = score
            best_match = cat

    if max_score >= 1:
        return best_match

    # 3. fallback_text => إنشاء تصنيف جديد من نص fallback
    if fallback_text:
        return to_slug(fallback_text)

    # 4. إذا لا شيء، تخمين بسيط
    return guess_fallback_category(text)


if __name__ == "__main__":
    text_ocr = "Here is some text about coffee, with no category keywords."
    filename = "randomfile_123.pdf"
    fallback = "Coffee Shop"

    category = classify_document(text_ocr, filename, fallback)
    print("تصنيف الوثيقة:", category)
