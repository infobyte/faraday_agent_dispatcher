#! /usr/bin/env bash

# If we can write an agent in any language we want, why not writing one in brainfuck?

read -d '' -r code <<'EOF'

--[-->+++++<]>.+[---->+<]>+++.[->+++<]>++.+++++++.++++.+.-.+[-->+++++<]>.[----->
+<]>.[-->+<]>+++.--[->+++<]>+.>--[-->+++++<]>.+[---->+<]>+++.+[->+++<]>.+++++++.
-[--->+<]>---.[----->+<]>.[-->+<]>+++.++.[-->+++<]>--.+.+++++.---------.++.--.++
.--.+++.++[--->++<]>.++++++++++.------------.++.-[->+++<]>+.+.[--->+<]>----.+++[
->+++<]>+.-[--->+<]>----.---------.+++++++.++++.-----------.++++++.-.--[++>---<]
>.[----->+<]>.[-->+<]>+++.++.>-[--->+<]>-.[---->+++++<]>-.---.--[--->+<]>-.-[---
>++<]>--.+++++++.++++.+.[---->+<]>+++.+[->+++<]>.-[--->+<]>----.-------------.--
--.--[--->+<]>-.+++[->+++<]>.-.-[--->+<]>-.[->+++<]>++.[--->+<]>+++.-[---->+<]>+
+.---[->++++<]>.------------.---.--[--->+<]>-.+[->++<]>.---[----->+<]>-.+++[->++
+<]>++.++++++++.+++++.--------.-[--->+<]>--.+[->+++<]>+.++++++++.-[++>---<]>+.[-
>+++<]>+.++++++.--.+++++++++.++++++.[-->+++++<]>.++++++++++.------------.++.[---
-->++<]>++.-.---------.++.---------.+++++++++++++.+++[->+++<]>++.+.+++++++.+++.-
--.+++++++++++.-----------.----.[--->+<]>----.+[-->+++++<]>.[----->+<]>.[-->+<]>
+++.--[->+++<]>+.>--[-->+++++<]>.+[---->+<]>+++.[--->++<]>++.-------------.+++++
+++++++.--------.+[--->+<]>.[----->+<]>.[-->+<]>+++.++.--[-->+++++<]>.[--->+<]>-
.+++++.+++[->+++<]>.+++++++++.++++++.-----------.--------.+++++++++++.[++>---<]>
--.[-->+++++++<]>.--------.[--->+<]>+.------.----------.------.--.+++++++++++.[+
+>---<]>--.+[----->+<]>.------------.++.+++++.+.+++++.---------.--[--->+<]>-.+[-
>+++<]>+.+.[--->+<]>----.+.--.+++.+[->+++<]>+.-[--->+<]>--.-----------.++++++.-.
--[++>---<]>.++++++++++.------------.++.-[->+++<]>+.+.[--->+<]>----.+++[->+++<]>
+.[--->+<]>+.[----->+<]>.[-->+<]>+++.++.>-[--->+<]>-.[---->+++++<]>-.---.--[--->
+<]>-.+[->+++<]>+.+.[--->+<]>-.+[->+++<]>.+++++++.+++.+.-----------.++++++++++++
+.[-->+++++<]>+++.-[--->++<]>-.++++++++++.+[---->+<]>+++.---[->++++<]>+.--.-----
-----.+++++.-------.-[--->+<]>--.+[->++<]>.---[----->+<]>-.+++[->+++<]>++.++++++
++.+++++.--------.-[--->+<]>--.+[->+++<]>+.++++++++.+++[----->++<]>.------------
.[->+++<]>+.-[->+++<]>.++[--->++<]>.-----------.+++++++++++++.-------.--[--->+<]
>--.[->+++<]>++.++++++.--.--[--->+<]>-.---[->++++<]>.------------.-------.--[---
>+<]>-.[---->+<]>+++.+[->+++<]>.++++++++++++.++++++.---------.--------.-[--->+<]
>-.+[----->+<]>.------------.++++++++++.------.--[--->+<]>-.-[--->++<]>--.---.++
+++++++++++.++[++>---<]>+.[--->+<]>+++.+.++++.[->+++++<]>-.++[->+++<]>.-[--->+<]
>--.---.---------.++++++.++++++.--.+[---->+<]>+++.[->+++<]>+.+++++++++++++.-----
-----.-[--->+<]>-.+[->+++<]>+.+.[--->+<]>----.+.--.---.++++++++++.-[---->+<]>++.
---[->++++<]>.------------.---.--[--->+<]>-.+[----->+<]>.------------.++.+++++.+
.+++++.---------.[->+++<]>-.++[--->++<]>.>-[--->+<]>-.[---->+++++<]>-.+.++++++++
++.+[---->+<]>+++.+[->+++<]>.++++++++++++.++++++.---------.--------.-[--->+<]>-.
---[----->++<]>.-------------.[--->+<]>----.++.---------.++++++++.[---->+<]>+++.
-[--->++<]>-.+++++.-[->+++++<]>-.---[->++++<]>-.----------.--.+++++++.-----.---.
+++.------.--.+++++++++++++.++++++.[---->+<]>+++.++[--->++<]>.+++.++++..++++[->+
++<]>.[--->+<]>----.+[---->+<]>+++.++[->+++<]>.+++++++++.+++.[-->+++++<]>+++.---
[->++++<]>.------------.---.--[--->+<]>-.+[->+++<]>.++++++++++++.--.+++.[----->+
+<]>+.+++++++++++++.[--->+<]>-.-[---->+<]>++++.++++++++++.------------.++.++++[-
>+++<]>.-------------.[--->+<]>----.----.---.+++++++++.-.-----------.++++++.-.--
[++>---<]>.[----->+<]>.[-->+<]>+++.++.++++[->++<]>+.[--->+<]>.+++++++.+[->+++<]>
.--[--->+<]>-.---[->++++<]>.-----.[--->+<]>-----.[->+++<]>+.+++++++++++++.+.++++
+.------------.---.+++++++++++++.[-->+++++<]>+++.+[->+++<]>++.[--->+<]>----.----
.+++++.------------.---.+++++++++++++.---------.------.[--->+<]>-.[-->+++++++<]>
.++.---.--------.+++++++++++.+++[->+++<]>++.++++++++++++.----.+++++.-------.-[--
->+<]>--.++[--->++<]>.-----------.+++++++++++++.-------.--[--->+<]>--.[->+++<]>+
+.++++++.--.[->+++<]>-.++[--->++<]>.---[->+++<]>.++[->++++<]>+.--[--->+<]>-.---[
----->++<]>.-------------.--.++++++++++++.--..--------.+++++++++.----------.-[--
->+<]>-.---[->++++<]>.------------.---.--[--->+<]>-.---[->++++<]>+.--.++[->+++<]
>++.++++++.--.--[--->+<]>-.+++++[->+++<]>.---------.[--->+<]>--.[-->+++++<]>+.-[
--->+<]>++.---------.++++++.---..+++.[--->+<]>-----.++++++++.[->+++++++++<]>.+++
+++++++++..----.[-->+<]>++.-----------..+[----->+<]>+.+.---------.++++++.---..++
+.[->+++++<]>+++.+[--->+<]>++.++.+++++++++++.------------.[--->+<]>---.+[->+++<]
>.[-->+<]>---.+[--->+<]>++++.++++++.+[->+++++<]>-.------.-------.++++++++++.----
--------.++.+[->+++<]>.++++.+++.[----->++<]>+.++.-[--->+<]>--.[-->+++++<]>.[----
->+<]>.[-->+<]>+++.-[->++++<]>-.+[---->+<]>+++.+[--->+<]>.+[--->+<]>.[->+++<]>-.
++++++++.+++.-----------.+.+++++++.+++.---.+++++++++++.+++++.-[---->+<]>++++.[--
--->+<]>.[-->+<]>+++.---[->++++<]>.--.+++.++[->+++<]>.>--[-->+++<]>.+[--->+<]>++
.------------.++.[----->++<]>-.++++[->+++<]>.[--->+<]>-.+[->+++<]>.+++++++++++++
.---------.+++++++++++.+++++.-[---->+<]>++++.[----->+<]>.[-->+<]>+++.++.[->+++<]
>++.+.--.+.--[--->+<]>.++++++++++.------------.++.[----->++<]>.+++++.---------.-
----------.+[--->+<]>.[----->+<]>.[-->+<]>+++.++.>+[--->++<]>.[--->+<]>+++.-----
----.++.---------.+++++++++++++.+++[->+++<]>++.+.+++++++.+++.---.+++++++++++.+++
++.-[---->+<]>++++.>--[-->+++<]>.-[---->+++<]>.>--[-->+++<]>.-[---->+++<]>.>--[-
->+++<]>.>++++++++++.

EOF

# Note: the previous brainfuck code generates the following JSON output:
# {"hosts": [{"ip": "127.0.0.1", "description": "The host created by the Brainfuck agent", "vulnerabilities": [{"name": "Potential physical machine destruction", "desc": "The developer is using Brainfuck, a language that could make her/him furious and destroy the machine. This could result in significant losses for the company", "resolution": "Move to another esotheric programing language. We recommend the usage of Qriollo (http://qriollo.github.io/)", "impact": {"availability": true}, "severity": "high", "type": "Vulnerability"}]}]}

CELLS=500
buffer=()
stack=()
ap=0

# Fill the buffer with zeros
for i in `seq 1 $CELLS`; do
    buffer+=(0)
done

for ((ip = 0; ip < ${#code}; ip++ )); do # ip is our instruction pointer
    op=${code:$ip:1}
    case "$op" in
        '[') 
            if [[ ${buffer[$ap]} == 0 ]]; then
                depth=1
                while [[ $depth > 0 ]]; do
                    ((ip++))
                    op=${code:$ip:1}
                    if [[ "$op" == '[' ]]; then
                        ((depth++))
                    elif [[ "$op" == ']' ]]; then
                        ((depth--))
                    fi
                done
            else
                stack+=($ip) 
            fi
            ;;
        ']') 
            if [[ ${buffer[$ap]} != 0 ]]; then
                ((ip = stack[${#stack[@]}-1]))
            else
                unset stack[${#stack[@]}-1]
            fi
            ;;

        '>') ((ap=(ap+1) % CELLS)) ;;
        '<') ((ap=(ap==0) ? CELLS-1 : ap-1)) ;;

        '+') ((buffer[ap]=(buffer[ap]+1) % 256)) ;;
        '-') ((buffer[ap]=(buffer[ap]==0) ? 255 : buffer[ap]-1)) ;;

        '.') printf "\x$(printf %x ${buffer[$ap]})" ;;
        ',') buffer[$ap]=$(read -n 1 && printf "%d" "'$REPLY") ;;
    esac
done
