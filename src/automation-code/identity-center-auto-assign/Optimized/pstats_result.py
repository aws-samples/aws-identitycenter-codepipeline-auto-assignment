import pstats
p = pstats.Stats('profile_assign.prof')

with open('profile_assign.txt', 'w') as f:
    p.stream = f
    p.print_stats()