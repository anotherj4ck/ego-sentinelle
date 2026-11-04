"""Rapport HTML d'Ego : document autonome, statique et sûr.

Deux fonctions de rendu, et seulement deux :
- _texte : valeur brute, neutralisée puis échappée ;
- _replique_html : valeurs déjà neutralisées, substituées dans le modèle, puis
  chaîne entière échappée. Les noms déjà neutralisés par formater_compte(s)
  passent par elle avec le modèle interne CHAMP_SEUL : neutraliser() n'est pas
  idempotent, une seconde neutralisation doublerait encore les « \\ ».
Aucune valeur dynamique n'entre dans un attribut : tous les attributs sont
écrits ici, en dur.
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
from ego.lecture import LigneRejetee
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
# Minimal : l'esthétique d'Ego viendra plus tard.
STYLE = """\
body { font-family: system-ui, sans-serif; line-height: 1.5;
       max-width: 60rem; margin: 0 auto; padding: 1rem; }
dt { font-weight: bold; }
.etat { font-weight: bold; letter-spacing: 0.1em; }
.replique { font-style: italic; }
table { border-collapse: collapse; }
th, td { border: 1px solid; padding: 0.25rem 0.5rem; text-align: left; }"""


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
        etat = "ALERTE · CODE 1"
        fin = _replique_html(modeles.conclusion, graine, communs)
    else:
        titre = _optionnelle(
            modeles.titre_calme, graine, {"total": str(total_echecs)}, TITRE_NEUTRE
        )
        etat = "SILENCE · CODE 0"
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
        "<body>",
        "<header>",
        '<dl class="entete">',
        f"<dt>Source</dt><dd>{_texte(nom_source)}</dd>",
        f"<dt>Période</dt><dd>{_texte(_periode(periode))}</dd>",
        f"<dt>Seuil</dt><dd>{_texte(_seuil(seuil, fenetre))}</dd>",
        f"<dt>Volume lu</dt><dd>{_texte(volume)}</dd>",
        "</dl>",
        f'<p class="etat">{_texte(etat)}</p>',
        "</header>",
        "<main>",
        f"<h1>{titre}</h1>",
        f'<p class="replique">{_replique_html(modeles.entete, graine, communs)}</p>',
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
    lignes = ['<section class="alertes">', "<h2>Alertes</h2>"]
    for alerte, variantes, rang in blocs[:ALERTES_MAX_AFFICHEES]:
        lignes += _bloc_alerte(alerte, variantes, graine + rang, communs)
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
) -> list[str]:
    # str(ip) peut porter un identifiant de zone arbitraire (fe80::1%<zone>) :
    # neutralisé comme un nom de compte.
    valeurs = {
        **communs,
        **valeurs_alerte(alerte),
        "ip": neutraliser(str(alerte.ip)),
    }
    origine = "locale" if alerte.est_locale else "externe"
    fenetre_du_pic = (
        _periode((alerte.debut_pic, alerte.fin_pic))
        + f" ({formater_duree(alerte.fin_pic - alerte.debut_pic)})"
    )
    comptes = _replique_html(CHAMP_SEUL, 0, {"valeur": valeurs["comptes"]})
    return [
        f'<article class="alerte {origine}">',
        f"<h3>{_texte(str(alerte.ip))}</h3>",
        "<dl>",
        f"<dt>Origine</dt><dd>{origine}</dd>",
        f"<dt>Pic</dt><dd>{_texte(_quantite(alerte.pic, 'échec', 'échecs'))}</dd>",
        f"<dt>Fenêtre du pic</dt><dd>{_texte(fenetre_du_pic)}</dd>",
        f"<dt>Total</dt><dd>{_texte(_quantite(alerte.total, 'échec', 'échecs'))}</dd>",
        f"<dt>Comptes visés</dt><dd>{comptes}</dd>",
        "</dl>",
        f'<p class="replique">{_replique_html(variantes, rang, valeurs)}</p>',
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
        '<section class="rejets">',
        "<h2>Lignes rejetées</h2>",
        "<table>",
        "<thead><tr><th>Ligne</th><th>Raison</th><th>Détail</th></tr></thead>",
        "<tbody>",
    ]
    for rejet in rejets[:REJETS_MAX_AFFICHES]:
        lignes.append(
            f"<tr><td>{_texte(str(rejet.numero))}</td>"
            f"<td>{_texte(rejet.raison.value)}</td>"
            f"<td>{_texte(rejet.detail)}</td></tr>"
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
    lignes = [
        '<section class="registre">',
        "<h2>Registre</h2>",
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


def _quantite(nombre: int, singulier: str, pluriel: str) -> str:
    # Règle française : 0 et 1 au singulier.
    return f"{nombre} {pluriel if nombre > 1 else singulier}"


def _autres(nombre: int) -> str:
    return _quantite(nombre, "autre", "autres")
