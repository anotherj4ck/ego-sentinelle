"""Rapport HTML d'Ego : document autonome, statique et sûr.

Deux fonctions de rendu, et seulement deux :
- _texte : valeur brute, neutralisée puis échappée ;
- _replique_html : valeurs déjà neutralisées, substituées dans le modèle, puis
  chaîne entière échappée. Les noms déjà neutralisés par formater_compte(s)
  passent par elle avec le modèle interne CHAMP_SEUL : neutraliser() n'est pas
  idempotent, une seconde neutralisation doublerait encore les « \\ ».
Aucune valeur dynamique n'entre dans un attribut : tous les attributs sont
écrits ici, en dur.

Esthétique : un vidage de mémoire du noyau d'Ego. Le décor (nerf, fente,
craquelures, séparateurs, adresses de marge) porte aria-hidden="true" ; les
informations restent lisibles par un lecteur d'écran.
"""

import html
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import PurePath, PureWindowsPath

from ego._redaction import (
    ALERTES_MAX_AFFICHEES,
    REJETS_MAX_AFFICHES,
    formater_compte,
    formater_comptes,
    formater_duree,
    formater_instant,
    graine as calculer_graine,
    remplir,
    valeurs_alerte,
)
from ego.detection import Alerte
from ego.lecture import LigneRejetee, SansIP
from ego.modeles import Modeles
from ego.neutralisation import neutraliser
from ego.registre import Registre, collecter_registre

TITRE_NEUTRE = "Rapport de surveillance"
REGISTRE_NEUTRE = "Registre"
FIN_NEUTRE = "Fin du rapport"
PERIODE_VIDE = "aucun événement lu"
POINT_MEDIAN = " · "
FLECHE = " → "
CHAMP_SEUL = ("$valeur",)
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none';"
    " form-action 'none'"
)

# Décor : textes fixes, toujours sous aria-hidden.
MASQUE = ' aria-hidden="true"'
SYSTEME = "∆ SYSTÈME EGO // ARCHIVE — SENTINELLE"
NOYAU = "∆ NOYAU BYPASS // CORROMPU À "
CORRUPTION = "42 %"
OCTETS = {
    "alerte": "░░ 4E 0A ▒▒ 00 00 ░ 7F ∆ ▒░ 3A 2D 2D ░░░",
    "silence": "░░ 00 00 ░ 00 ∆ ░░ 00 00 00 ░░░",
}
REMPLISSAGE = "░" * 32
ETIQUETTES = {
    "externe": " · ALERTE · EXTERNE",
    "locale": " · LOCAL · SANS DOUTE UN TEST",
    # Échecs « - » : écran de connexion ou de déverrouillage, services… Pas un test.
    "sans_ip": " · LOCAL · CLAVIER OU SERVICE",
}
PAS_D_ADRESSE = 0xA0  # adresses de marge : 0x00A0, 0x0140, 0x01E0…
CRAQUELURES = (
    "M59 30 C 48 40, 40 38, 30 52 S 12 66, 2 70",
    "M59 70 C 46 86, 36 84, 24 100 S 10 118, 0 126",
    "M61 50 C 74 58, 88 56, 98 70 S 112 84, 120 88",
    "M61 110 C 76 124, 84 130, 100 140",
    "M30 52 C 26 60, 18 64, 12 76",
)

# Polices système seulement ; aucune url(), aucun @import. Couleurs en variables :
# le texte respecte 4,5:1 sur son fond ; --decor-* ne sert qu'au décor masqué.
STYLE = """\
:root {
  --fond: #0A0706; --texte: #ECE5D8; --voix: #E9DFCF; --gris: #8F8577;
  --orange: #FF6A2B; --signal: #FF7A3D; --ambre: #F0B43C; --ambre-voix: #F0C36A;
  --code: #1E1614; --badge-calme: #241A17; --braise: #E2541F;
  --decor: #3E3530; --decor-adresse: #5F564C;
}
* { box-sizing: border-box; }
html, body { background: var(--fond); }
body {
  margin: 0; padding: 0 16px; color: var(--texte);
  font-family: Consolas, "Cascadia Mono", ui-monospace, monospace;
  font-size: 14px; line-height: 1.7;
}
.page {
  position: relative; max-width: 1000px; margin: 0 auto; padding: 0 0 72px 108px;
}
.nerf {
  position: absolute; left: 64px; top: 0; bottom: 0; width: 2px;
  background: linear-gradient(#FFF1DC 0, #FF7A3D 90px, #B3261E 260px,
    #5A1A10 70%, rgba(90, 26, 16, 0) 100%);
  box-shadow: 0 0 10px rgba(255, 106, 43, 0.6);
  animation: pulsation 2.6s ease-in-out infinite;
}
.fente {
  position: absolute; left: 61px; top: 28px; width: 8px; height: 64px;
  border-radius: 4px; background: #FFF4E4;
  box-shadow: 0 0 18px 6px rgba(255, 140, 80, 0.55),
    0 0 60px 14px rgba(226, 84, 31, 0.35);
}
.craquelures {
  position: absolute; left: 6px; top: 40px; width: 120px; height: 220px;
  fill: none; stroke: var(--braise); stroke-linecap: round; stroke-width: 0.8;
  animation: pulsation 2.6s ease-in-out infinite;
}
.craquelures path:first-child { stroke-width: 1; }
.craquelures path:nth-child(n+4) { stroke-width: 0.6; }
.etat-silence .nerf {
  background: linear-gradient(#C98A6A 0, #8E3518 120px, #3A140C 60%,
    rgba(58, 20, 12, 0) 100%);
  box-shadow: 0 0 6px rgba(142, 53, 24, 0.45); animation-duration: 6s;
}
.etat-silence .fente {
  left: 62px; top: 48px; width: 6px; height: 22px; border-radius: 3px;
  background: #F5D9C2; box-shadow: 0 0 12px 4px rgba(194, 85, 46, 0.4);
}
.etat-silence .craquelures { display: none; }
@keyframes pulsation { 50% { opacity: 0.55; } }
@keyframes fievre {
  0%, 90%, 100% { opacity: 1; transform: none; }
  91% { opacity: 0.35; transform: translateX(3px); }
  93% { opacity: 1; transform: translateX(-2px); }
  95% { opacity: 0.55; transform: none; }
}
.fievre { display: inline-block; animation: fievre 5s steps(1) infinite; }
header { position: relative; padding-top: 40px; font-size: 13px; }
.machine { margin: 0; color: var(--signal); letter-spacing: 0.12em; }
.octets, .separateur {
  margin: 0; color: var(--decor); letter-spacing: 0.2em;
  white-space: nowrap; overflow: hidden;
}
.separateur { margin-top: 48px; font-size: 13px; }
dl { display: grid; grid-template-columns: 8.5rem minmax(0, 1fr); margin: 0; }
.entete { margin-top: 10px; }
dt { color: var(--gris); text-transform: lowercase; }
dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.etat {
  display: grid; grid-template-columns: 8.5rem auto; justify-content: start;
  margin: 0;
}
.cle { color: var(--gris); }
.badge {
  padding: 0 8px; font-weight: 700; letter-spacing: 0.08em;
  color: var(--fond); background: var(--orange);
}
.etat-silence .badge { color: var(--texte); background: var(--badge-calme); }
code {
  padding: 0 4px; color: var(--texte); background: var(--code);
  font-family: Consolas, "Cascadia Mono", ui-monospace, monospace;
  overflow-wrap: anywhere;
}
h1, .replique {
  color: var(--voix); font-family: Georgia, "Times New Roman", serif;
  font-style: italic; font-weight: 400; overflow-wrap: anywhere;
}
h1 { margin: 48px 0 8px; font-size: 52px; line-height: 1.1; }
.replique {
  max-width: 720px; margin: 14px 0 0 24px; font-size: 18px; line-height: 1.65;
}
main > .replique { margin: 0 0 0 28px; font-size: 19px; }
.alerte { display: flex; margin: 28px 0 0 -108px; }
.adresse {
  flex: none; width: 64px; padding-top: 3px;
  font-size: 12px; color: var(--decor-adresse);
}
.noeud { flex: none; position: relative; width: 44px; }
.fil {
  position: absolute; left: 0; top: 13px; width: 36px; height: 1px;
  background: var(--braise); box-shadow: 0 0 6px var(--braise);
}
.locale .fil { background: var(--ambre); box-shadow: 0 0 6px var(--ambre); }
.corps { flex: 1; min-width: 0; }
h3 {
  margin: 0; font-size: 17px; letter-spacing: 0.04em;
  color: var(--orange); overflow-wrap: anywhere;
}
.etiquette { font-size: 12px; font-weight: 400; letter-spacing: 0.12em; }
.locale h3 { color: var(--ambre); }
.locale .replique { color: var(--ambre-voix); }
.reste { margin: 12px 0 0; color: var(--gris); }
.rejets table { margin: 16px 0 0 -108px; border-collapse: collapse; }
.rejets th, .rejets td { padding: 0 12px 0 0; text-align: left; vertical-align: top; }
.rejets td:first-child { width: 108px; font-size: 12px; color: var(--gris); }
.rejets td:first-child::before { content: "l. "; }
.rejets td:nth-child(2) { color: var(--gris); }
.registre .replique { margin: 16px 0 12px; font-size: 22px; }
.registre ul {
  margin: 0; padding: 0; list-style: none; font-size: 13px; line-height: 2;
  color: var(--gris); letter-spacing: 0.03em;
}
.registre li { display: inline; overflow-wrap: anywhere; }
.registre li + li::before { content: " — "; }
.fin { margin-top: 56px; }
.fin .replique:last-child {
  margin-left: 0; color: var(--signal); font-style: normal; font-size: 12px;
  font-family: Consolas, "Cascadia Mono", ui-monospace, monospace;
  letter-spacing: 0.12em; text-transform: uppercase;
}
footer { margin-top: 8px; font-size: 12px; color: var(--gris); }
footer p { margin: 0; }
.visuellement-masque {
  position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; }
}
@media (max-width: 600px) {
  .page { padding-left: 40px; }
  .nerf { left: 16px; }
  .fente, .etat-silence .fente { left: 13px; }
  .craquelures { display: none; }
  .alerte, .rejets table { margin-left: -40px; }
  .adresse { display: none; }
  .noeud { width: 40px; }
  .fil { left: 17px; width: 19px; }
  .rejets td:first-child { width: 40px; padding-right: 4px; white-space: nowrap; }
  dl, .etat { grid-template-columns: minmax(0, 1fr); }
  h1 { font-size: 34px; }
  .replique, main > .replique { margin-left: 0; }
}
@media print {
  *, *::before, *::after {
    color: #000 !important; background: #fff !important;
    box-shadow: none !important; animation: none !important;
  }
  [aria-hidden="true"] { display: none !important; }
  .page { padding-left: 0; }
  .alerte, .rejets table { margin-left: 0; }
  section { margin-top: 24px; }
  .visuellement-masque {
    position: static; width: auto; height: auto; margin: 0;
    overflow: visible; clip: auto; white-space: normal;
  }
}"""


def rediger_html(
    alertes: Sequence[Alerte],
    rejets: Sequence[LigneRejetee],
    seuil: int,
    fenetre: timedelta,
    modeles: Modeles,
    *,
    total_echecs: int,
    origines: int,
    periode: tuple[datetime, datetime] | None,
    source: str | PurePath,
    genere_le: datetime,
) -> str:
    """Document HTML complet. Fonction pure : aucune lecture, aucune horloge.

    Mêmes variantes que rediger() pour les répliques communes. Seul le nom du
    fichier source est affiché, jamais son chemin (il contiendrait le nom de
    l'utilisateur Windows). Lève ValueError si genere_le n'a pas de fuseau.
    """
    if genere_le.utcoffset() is None:
        raise ValueError(f"genere_le sans fuseau horaire : {genere_le}")
    graine = calculer_graine(alertes, rejets)
    communs = {"seuil": str(seuil), "fenetre": formater_duree(fenetre)}
    # PureWindowsPath coupe sur « \ » comme sur « / », quel que soit le système.
    nom_source = PureWindowsPath(str(source)).name
    if alertes:
        titre = _optionnelle(
            modeles.titre_alerte, graine, {"nombre": str(len(alertes))}, TITRE_NEUTRE
        )
        etat, ambiance = "ALERTE · CODE 1", "alerte"
        fin = _replique_html(modeles.conclusion, graine, communs)
    else:
        titre = _optionnelle(
            modeles.titre_calme, graine, {"total": str(total_echecs)}, TITRE_NEUTRE
        )
        etat, ambiance = "SILENCE · CODE 0", "silence"
        fin = _replique_html(modeles.rien_a_signaler, graine, communs)
    volume = POINT_MEDIAN.join(
        [
            _quantite(total_echecs, "échec", "échecs"),
            _quantite(origines, "origine", "origines"),
            _quantite(len(rejets), "ligne rejetée", "lignes rejetées"),
        ]
    )
    # Section omise sans alerte ; calculé sur toutes les alertes, même masquées.
    registre = (
        _section_registre(collecter_registre(alertes), modeles, graine)
        if alertes
        else []
    )
    fin_lecture = _optionnelle(modeles.fin_lecture, graine, {}, FIN_NEUTRE)
    craquelures = "".join(f'<path d="{trace}"/>' for trace in CRAQUELURES)
    lignes = [
        "<!DOCTYPE html>",
        '<html lang="fr">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="referrer" content="no-referrer">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_texte(TITRE_NEUTRE + POINT_MEDIAN + nom_source)}</title>",
        f"<style>\n{STYLE}\n</style>",
        "</head>",
        f'<body class="etat-{ambiance}">',
        '<div class="page">',
        f'<div class="nerf"{MASQUE}></div>',
        f'<div class="fente"{MASQUE}></div>',
        f'<svg class="craquelures" viewBox="0 0 120 220"{MASQUE}>{craquelures}</svg>',
        "<header>",
        f'<p class="machine"{MASQUE}>{_texte(SYSTEME)}</p>',
        f'<p class="machine"{MASQUE}>{_texte(NOYAU)}'
        f'<span class="fievre">{_texte(CORRUPTION)}</span></p>',
        f'<p class="octets"{MASQUE}>{_texte(OCTETS[ambiance])}</p>',
        '<dl class="entete">',
        f"<dt>Source</dt><dd><code>{_texte(nom_source)}</code></dd>",
        f"<dt>Période</dt><dd>{_texte(_periode(periode))}</dd>",
        f"<dt>Seuil</dt><dd>{_texte(_seuil(seuil, fenetre))}</dd>",
        f"<dt>Volume lu</dt><dd>{_texte(volume)}</dd>",
        "</dl>",
        '<p class="etat"><span class="cle">état</span>'
        f'<span class="badge">{_texte(etat)}</span></p>',
        "</header>",
        "<main>",
        f"<h1>{titre}</h1>",
        f'<p class="replique">{_replique_html(modeles.entete, graine, communs)}</p>',
        _separateur("SUJETS", f"{len(alertes):02d}"),
        *_section_alertes(alertes, modeles, graine, communs),
        *_section_rejets(rejets, modeles, graine, communs),
        *registre,
        '<section class="fin">',
        f'<p class="replique">{fin}</p>',
        f'<p class="replique">{fin_lecture}</p>',
        "</section>",
        "</main>",
        "<footer>",
        f"<p>{_texte(f'Généré le {formater_instant(genere_le)}')}"
        " · fichier statique, aucun script</p>",
        "</footer>",
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(lignes) + "\n"


def _texte(brut: str) -> str:
    """Valeur brute : neutralisée, puis échappée pour HTML."""
    return html.escape(neutraliser(brut), quote=True)


def _replique_html(
    variantes: tuple[str, ...], rang: int, valeurs: Mapping[str, str]
) -> str:
    """Valeurs déjà neutralisées, substituées, puis chaîne entière échappée."""
    return html.escape(remplir(variantes, rang, valeurs), quote=True)


def _optionnelle(
    variantes: tuple[str, ...] | None,
    rang: int,
    valeurs: Mapping[str, str],
    neutre: str,
) -> str:
    if variantes is None:
        return _texte(neutre)
    return _replique_html(variantes, rang, valeurs)


def _separateur(libelle: str, compteur: str) -> str:
    """Ligne d'octets corrompus, décorative, avec un compteur réel."""
    ligne = f"▒░ ∆ {libelle} ░▒ {compteur} {REMPLISSAGE}"
    return f'<div class="separateur"{MASQUE}>{_texte(ligne)}</div>'


def _section_alertes(
    alertes: Sequence[Alerte],
    modeles: Modeles,
    graine: int,
    communs: Mapping[str, str],
) -> list[str]:
    if not alertes:
        return []
    # Externes puis locales, chaque section avec sa propre rotation : comme rediger().
    externes = [a for a in alertes if not a.est_locale]
    locales = [a for a in alertes if a.est_locale]
    blocs = [
        *((a, modeles.alerte, rang) for rang, a in enumerate(externes)),
        *((a, modeles.alerte_locale, rang) for rang, a in enumerate(locales)),
    ]
    lignes = [
        '<section class="alertes">',
        '<h2 class="visuellement-masque">Alertes</h2>',
    ]
    for position, (alerte, variantes, rang) in enumerate(
        blocs[:ALERTES_MAX_AFFICHEES], start=1
    ):
        adresse = f"0x{position * PAS_D_ADRESSE:04X}"
        lignes += _bloc_alerte(alerte, variantes, graine + rang, communs, adresse)
    masquees = len(blocs) - ALERTES_MAX_AFFICHEES
    if masquees > 0:
        reste = _quantite(masquees, "alerte non affichée", "alertes non affichées")
        lignes.append(f'<p class="reste">{_texte(f"+ {reste}")}</p>')
    lignes.append("</section>")
    return lignes


def _bloc_alerte(
    alerte: Alerte,
    variantes: tuple[str, ...],
    rang: int,
    communs: Mapping[str, str],
    adresse: str,
) -> list[str]:
    valeurs = {**communs, **valeurs_alerte(alerte)}  # IP et comptes neutralisés
    origine = "locale" if alerte.est_locale else "externe"  # classe CSS : ambre ou orange
    etiquette = ETIQUETTES["sans_ip" if isinstance(alerte.ip, SansIP) else origine]
    fenetre_du_pic = (
        _periode((alerte.debut_pic, alerte.fin_pic))
        + f" ({formater_duree(alerte.fin_pic - alerte.debut_pic)})"
    )
    comptes = _replique_html(CHAMP_SEUL, 0, {"valeur": valeurs["comptes"]})
    pic = (
        f"<strong>{_texte(str(alerte.pic))}</strong>"
        f" {_texte(_mot(alerte.pic, 'échec', 'échecs'))}"
    )
    # Titre : l'IP brute, que _texte neutralise une fois. Jamais valeurs["ip"],
    # déjà neutralisée : neutraliser() n'est pas idempotent.
    return [
        f'<article class="alerte {origine}">',
        f'<span class="adresse"{MASQUE}>{_texte(adresse)}</span>',
        f'<span class="noeud"{MASQUE}><span class="fil"></span></span>',
        '<div class="corps">',
        f'<h3><span class="marque"{MASQUE}>∆ SUJET </span>{_texte(str(alerte.ip))}'
        f'<span class="etiquette"{MASQUE}>{_texte(etiquette)}</span></h3>',
        "<dl>",
        # Origine : dite par l'étiquette à l'écran, gardée pour les lecteurs d'écran.
        '<dt class="visuellement-masque">Origine</dt>'
        f'<dd class="visuellement-masque">{origine}</dd>',
        f"<dt>Pic</dt><dd>{pic}</dd>",
        f"<dt>Fenêtre du pic</dt><dd>{_texte(fenetre_du_pic)}</dd>",
        f"<dt>Total</dt><dd>{_texte(_quantite(alerte.total, 'échec', 'échecs'))}</dd>",
        f"<dt>Comptes visés</dt><dd>{comptes}</dd>",
        "</dl>",
        f'<p class="replique">{_replique_html(variantes, rang, valeurs)}</p>',
        "</div>",
        "</article>",
    ]


def _section_rejets(
    rejets: Sequence[LigneRejetee],
    modeles: Modeles,
    graine: int,
    communs: Mapping[str, str],
) -> list[str]:
    if not rejets:
        return []
    lignes = [
        _separateur("SECTEURS ILLISIBLES", f"{len(rejets):02d}"),
        '<section class="rejets">',
        '<h2 class="visuellement-masque">Lignes rejetées</h2>',
        "<table>",
        '<thead class="visuellement-masque">'
        "<tr><th>Ligne</th><th>Raison</th><th>Détail</th></tr></thead>",
        "<tbody>",
    ]
    for rejet in rejets[:REJETS_MAX_AFFICHES]:
        lignes.append(
            f"<tr><td>{_texte(str(rejet.numero))}</td>"
            f"<td>{_texte(rejet.raison.value)}</td>"
            f"<td><code>{_texte(rejet.detail)}</code></td></tr>"
        )
    lignes += ["</tbody>", "</table>"]
    autres = len(rejets) - REJETS_MAX_AFFICHES
    if autres > 0:
        lignes.append(f'<p class="reste">{_texte(f"… et {_autres(autres)}")}</p>')
    valeurs = {**communs, "nombre": str(len(rejets))}
    replique = _replique_html(modeles.lignes_rejetees, graine, valeurs)
    lignes += [f'<p class="replique">{replique}</p>', "</section>"]
    return lignes


def _section_registre(registre: Registre, modeles: Modeles, graine: int) -> list[str]:
    valeurs = {"nombre": str(registre.total)}
    replique = _optionnelle(modeles.registre, graine, valeurs, REGISTRE_NEUTRE)
    noms = (
        _replique_html(CHAMP_SEUL, 0, {"valeur": formater_compte(nom)})
        for nom in registre.noms
    )
    entrees = _mot(registre.total, "ENTRÉE", "ENTRÉES")
    lignes = [
        _separateur("REGISTRE", f"{registre.total:02d} {entrees}"),
        '<section class="registre">',
        '<h2 class="visuellement-masque">Registre</h2>',
        f'<p class="replique">{replique}</p>',
        "<ul>",
        *(f"<li>{nom}</li>" for nom in noms),
        "</ul>",
    ]
    if registre.masques > 0:
        reste = _texte(f"+ {_autres(registre.masques)}")
        lignes.append(f'<p class="reste">{reste}</p>')
    lignes.append("</section>")
    return lignes


def _periode(periode: tuple[datetime, datetime] | None) -> str:
    if periode is None:
        return PERIODE_VIDE
    debut, fin = periode
    return f"{formater_instant(debut)}{FLECHE}{formater_instant(fin)}"


def _seuil(seuil: int, fenetre: timedelta) -> str:
    return f"{_quantite(seuil, 'échec', 'échecs')} en {formater_duree(fenetre)}"


def _mot(nombre: int, singulier: str, pluriel: str) -> str:
    # Règle française : 0 et 1 au singulier.
    return pluriel if nombre > 1 else singulier


def _quantite(nombre: int, singulier: str, pluriel: str) -> str:
    return f"{nombre} {_mot(nombre, singulier, pluriel)}"


def _autres(nombre: int) -> str:
    return _quantite(nombre, "autre", "autres")
