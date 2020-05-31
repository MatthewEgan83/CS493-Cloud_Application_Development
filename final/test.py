sub = "123456"
sub2 = '345677'
test = [{'id': 23456, 'owner': sub, 'mark': "beast"}, {'id': 345, 'owner': sub, 'mark': 'angel'}]

if not any (d['owner'] == sub2 for d in test):
	print ("it works!")
else:
	print("Doesn't work!")