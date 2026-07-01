from database import engine
import models

print("Database check kar rahe hain...")
# Ye command database mein check karegi aur jo tables missing hain unhe bana degi
models.Base.metadata.create_all(bind=engine)
print("Saari naye tables successfully ban gayi hain!")