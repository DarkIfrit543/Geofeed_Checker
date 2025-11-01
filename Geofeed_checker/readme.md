# IPXO GEOFEED CHECKER

Sis irankis padeda palyginti **IPXO „Marketplace“ (subnets)** su **kitu organizaciju Geofeed** duomenis.  
Skriptas automatiskai:
- Pasiima oficialu **IPXO geofeed** iš `https://geofeed.ipxo.com/geofeed.txt`;
- Perskaito visus failus is `geofeeds/` folderio;
- Jei tie failai yra **nuorodų sąrašai** (pvz., `https://example.net/geofeed.csv`), jis pats atsisiuncia ir apdoroja tuos geofeed’us;
- Randa visus IPXO subnetus, kurie pasirodo kituose geofeeduose;
- Sugeneruoja ataskaitas su sutampanciais irasais ir galimais salies neatitikimais.

---

## 📁 Katalogo struktūra

Struktura turi atrodyti taip:

Geofeed_checker/
├── geofeeds/
│ ├── afrinic-geofeeds.txt
│ ├── apnic-geofeeds.txt
│ ├── arin-geofeeds.txt
│ ├── lacnic-geofeeds.txt
│ └── ripe-geofeeds.txt
├── subnets.txt
├── ipxo_geofeed_checker.py
└── out/ (sukuriamas automatiškai po paleidimo)

### reikalingas paketas:
pip install certifi

#### Pasibaigus skanavimui
Atsiranda naujas aplankalas automatiskai pavadinimu ./out 
Jai bus atitikimu bus pakurtas matches.csv failas
run.log - pranesa apie sekminga pabaiga arba ne
summary_by_subnets.csv failas - jame galima pasiziuret pasikartojancius atitikimus, unikalius source'us ir 
reikalinga mums mismatch'a kuri matome matches.csv faile