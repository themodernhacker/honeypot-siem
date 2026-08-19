# Tuning the detections for the real world

## Why this write-up exists

The other three write-ups all follow the same happy shape: an attack happens, a
rule fires, the rule was right. That is the easy half of detection work. The hard
half, the half that actually fills a SOC analyst's day, is telling signal from
noise, and none of that shows up when you are only ever pointing the rules at a
honeypot where every single event is an attacker.

So this is the missing pass. Before any of these rules goes anywhere near a real
network, you have to ask a different question about each one: on a box that also
has legitimate users, how often does this fire when nothing is wrong, and what do
I do about it. This write-up walks through that for the recon rule, because it is
the clearest example, and then generalises.

## The problem, using rule 100107

Rule 100107 fires on discovery commands: `uname`, `id`, `whoami`,
`cat /etc/passwd`, and friends. In the honeypot that is a clean signal, nobody
legitimate is ever inside `web-prod-01`, so every hit is an attacker enumerating
the box.

On a real server it is the opposite. Those exact commands run all day for
completely boring reasons. Admins run `id` and `uname -a` by reflex. Config
management (Ansible gathering facts, for one) runs `uname`, `id`, and reads
`/etc/os-release` on every single run. Monitoring agents, cron jobs, and login
scripts poke at the same files. If I ship 100107 at level 8 as-is, it fires
hundreds of times a day on noise, the analyst learns within a week that it is
almost always nothing, and starts clicking past it. A rule everyone ignores is
worse than no rule, because it still costs attention and now gives false comfort.

None of that means the rule is bad. It means it is not finished. Here is how I
would take it the rest of the way.

## Move 1: baseline the environment and allowlist the known-good sources

The first job is to learn where the *legitimate* recon comes from, the jump
hosts, the bastion, the CI runners, the config-management master, and treat
traffic from those as expected. In Wazuh that is a CDB list kept in version
control next to the rules:

```
# etc/lists/known_admin_hosts   (ip : label)
10.0.10.5:bastion-1
10.0.10.6:bastion-2
10.0.20.11:ansible-master
```

Then a level 0 child rule that swallows recon from anything on that list, so it
is logged but never alerts:

```xml
<rule id="100150" level="0">
  <if_sid>100107</if_sid>
  <list field="src_ip" lookup="match_key">etc/lists/known_admin_hosts</list>
  <description>Recon command from a known admin host ($(src_ip)), expected, suppressed.</description>
</rule>
```

Being honest about the lab: I have not wired this into `local_rules.xml`, because
here there are no legitimate admins to allowlist, so the rule would have nothing
to suppress and I could not actually test it. The shape above is what I would add
on the day this pointed at a real fleet, and the allowlist itself would live in
git so every exception has an author and a reason attached to it.

## Move 2: alert on context, not on the bare command

A single `id` is not a 3am page. An `id` run three seconds after a login that came
straight off a brute-force burst is. The command is identical, the context is
everything, and that context is exactly what the earlier correlation rules already
capture.

Unlike Move 1, this one I actually wired into the lab (rule 100151), because the
attack scripts already produce recon-after-compromise so there is something real
to test it against. The tempting version is to turn the recon alert right down,
but that risks going blind to recon that arrives some other way (stolen key, a
different vector), so instead, with Move 1's allowlist already stripping out the
routine admin noise, I left 100107 at its review-worthy level 8 and layered a
higher-severity rule on top that only fires when recon follows the compromise
alert (100105) from the same source inside ten minutes:

```xml
<!-- 100107 stays a review-level recon alert (level 8, unchanged) -->

<!-- ... and this escalates it to a page when the recon is post-compromise -->
<rule id="100151" level="12" timeframe="600">
  <if_sid>100107</if_sid>
  <if_matched_sid>100105</if_matched_sid>
  <same_field>src_ip</same_field>
  <description>Cowrie: recon from $(src_ip) that already tripped post-brute-force compromise (100105), escalating.</description>
  <mitre><id>T1082</id><id>T1033</id></mitre>
</rule>
```

That gives a severity ladder instead of one flat alert: recon on its own stays a
level 8 "go look at this" signal, and recon from a source I have already confirmed
compromised jumps to level 12 to page, because at that point it is not someone
poking around, it is an attacker enumerating a box they just broke into. It is the
same composite pattern the compromise rule itself uses (`if_sid` plus
`if_matched_sid` plus `same_field`), and the detection-as-code suite in
[`../tests/`](../tests/) has a case that feeds a full brute-force-then-recon burst
through `wazuh-logtest` and asserts 100151 actually fires.

## Move 3: tune the thresholds and keep tuning them

The numbers in the correlation rules are lab defaults, not universal truths. The
brute-force rule (100104) fires at 8 failures in 120 seconds; the rapid-connection
rule (100110) at 12 connections in 60. Those are fine for a quiet honeypot. On a
real internet-facing edge with health checks, load balancers probing, and the odd
user genuinely locking themselves out, I would baseline what normal actually looks
like, set the threshold above the noise floor, and allowlist the known automated
talkers, vulnerability scanners and uptime monitors especially, so their bursts do
not masquerade as an attack.

The success-after-brute-force rule (100105) has a related caveat I called out in
[`MITRE-MAPPING.md`](MITRE-MAPPING.md) and the
[brute-force write-up](writeup-brute-force.md): it correlates on source IP only,
so behind one NAT a fumbled password plus a separate legitimate login can read as
a compromise. Same discipline applies, tighten it to key on IP and username to
page, and keep the looser IP-only version as a lower-severity flag.

## How you actually know it is tuned

The point of all of this is a number: the false-positive rate. In production I
would track how often each rule fires and what fraction an analyst closes as
benign, and I would treat a rule that is mostly benign the way I treat a failing
test, as a bug to fix rather than noise to live with. Allowlists and thresholds
go in version control right next to the rules, so a tuning change gets an author,
a reason, and a diff, exactly like any other code change.

## What I would do next as a detection engineer

Ship the rules at a sensible level, watch the real firing rate for a week or two,
and let the data drive the tuning: allowlist the sources that turn out to be
noise, promote the patterns that turn out to be real, and revisit it on a
schedule because environments drift. Detection engineering is not writing a rule
once and walking away, it is owning that rule's signal-to-noise ratio for as long
as it is switched on.
