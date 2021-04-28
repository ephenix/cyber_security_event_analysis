import boto3
import json
import math
from graphviz import Digraph

with open( "./events.json", "r" ) as jsonfile:
    records = json.load( jsonfile )

#print( len(records) )

#records_by_year = {}
#records_by_month = {}
#for record in records:
#    if record['year'] not in records_by_year:
#        records_by_year[record['year']] = []
#    records_by_year[record['year']].append( record )
#    if record['month']+record['year'] not in records_by_month:
#       records_by_month[record['month']+record['year']] = []
#    records_by_month[record['month']+record['year']].append( record )
#
#record_counts_by_month = { k:len(v) for k,v in records_by_month.items()}
#
#print( json.dumps(record_counts_by_month, indent=4) )

comprehend_client = boto3.client("comprehend")

keywords_groups = [
    [ "USA", "American", "U.S.", "US", "United States", "America", "Washington", "D.C.", "NSA", "FBI", "CIA", "NASA" ],
    [ "Canada", "Canadian", "Toronto", "Quebec", "Montreal" ],
    [ "Italy", "Italian" ],
    [ "United Nations", "UN", "U.N" ],
    [ "Facebook", "facebook" ],
    [ "Twitter", "twitter" ],
    [ "Google", "google" ],
    [ "Microsoft", "microsoft" ],
    [ "Apple" ],
    [ "Amazon", "AWS" ],
    [ "Russia", "Russian", "Moscow", "Kremlin" ],
    [ "China", "Chinese", "People's Liberation Army", "PLA" ],
    [ "Yemen" ],
    [ "India", "Indian"],
    [ "Norway", "Norwegian" ],
    [ "Chile", "Chilean" ],
    [ "North Korea", "North Korean", "N. Korea", "Pyongyang"],
    [ "South Korea", "South Korean", "S. Korea", "Seol"],
    [ "UK", "U.K.", "United Kingdom", "England", "English", "Britain", "British", "London", "BBC" ],
    [ "Lebanon"],
    [ "Finland", "Finnish"],
    [ "Iran", "Iranian" ],
    [ "Poland", "Polish" ],
    [ "New Zealand" ],
    [ "Australia", "Australian", "AUS" ],
    [ "UAE", "United Arab Emirates", "Dubai" ],
    [ "Pakistan" ],
    [ "Kazakhstan", "Kazakh" ],
    [ "Saudi Arabia", "Saudi" ],
    [ "Vietnam", "Vietnamese" ],
    [ "Mongolia" ],
    [ "Armenia" ],
    [ "Germany", "German" ],
    [ "France", "French" ],
    [ "Taiwan", "Taiwanese", "Thai" ],
    [ "Azerbaijan", "Azerbaijani" ],
    [ "Israel", "Israeli" ],
    [ "Tibet", "Tibetan" ],
    [ "Uyghur"],
    [ "Kurdistan", "Kurds", "Kurdish" ],
    [ "Turkey" ],
    [ "Syria" ],
    [ "Europe", "European", "EU", "E.U." ],
    [ "Asia" ],
    [ "Morocco", "Moroccan" ],
    [ "Japan", "Japanese", "Tokyo" ],
    [ "COVID-19"],
    [ "Ukraine", "Ukrainian"],
    [ "Oil", "oil", "Petroleum", "gas" ],
    [ "Crypto", "Bitcoin" ],
    [ "Bahrain", "Bahraini" ],
    [ "Africa", "African" ],
    [ "Mexico", "Mexican" ],
    [ "Bavaria", "Munich" ],
    [ "ISIS" ],
    [ "Al-Qaida" ],
    [ "Hamas" ],

]

def contains_keyword ( text, keywords ):
    hits = []
    for kwg in keywords_groups:
        for kw in kwg:
            if kw in text and kwg[0] not in hits:
                hits.append( kwg[0] )
    return hits

i = 0
graph = {}
dot = Digraph(comment="Cyber Security Events Mapping")
#dot.attr(rankdir="LR")
edge_dict = {}

record_count = 0
missed_count = 0

for record in reversed( records ):
    #print( record['description'] )
    #print( hits )
    #bins     = []
    #group    = ""
    #for token in syntax['SyntaxTokens']:
    #    if token['PartOfSpeech']['Tag'] == "VERB":
    #        item = {
    #            "type": "phrase",
    #            "text": group
    #        }
    #        bins.append( item )
    #        bins.append( { "type": "verb", "text": token['Text'] } )
    #        group = ""
    #    else:
    #        group += " " + token['Text']
    #item = {
    #        "type": "phrase",
    #        "text": group
    #    }
    #bins.append( item )
    #bins
    hits = contains_keyword( record['description'], keywords_groups )
    if len(hits) > 1:
        record_count += 1
        for hit in hits:
            dot.node( hit )
        for node_a in hits:
            if node_a not in edge_dict:
                edge_dict[node_a] = {}
            for node_b in hits:
                if node_b not in edge_dict:
                    edge_dict[node_b] = {}
                if node_a != node_b:
                    if node_b in edge_dict[ node_a ]:
                        edge_dict[ node_a ][ node_b ] = edge_dict[ node_a ][ node_b ] + 1
                    else:
                        edge_dict[ node_a ][ node_b ] = 1
        #print( edge_dict )
    else:
        missed_count += 1
        print( f"MISS # {missed_count}: ")
        print( "Text: " + record['description'])
        print( "Hits: " + str(hits) )

print( f"records w/ 2 or more entities: {record_count}" )
print( f"records w/ 1 or fewer entities: {missed_count}" )

#FILTER = [ "USA", "Russia", "China" ]

for entity, targets in edge_dict.items():
    for target, weight in targets.items():
        #if entity in FILTER or target in FILTER:
        edge_dict[ target ].pop( entity )
        dot.edge( entity, target, label=f"{entity}<->{target}: {weight}", penwidth=f"{math.log(weight*5)}" )

dot = dot.unflatten(stagger=20)
dot.view()