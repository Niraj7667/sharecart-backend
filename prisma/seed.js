// prisma/seed.js

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const main = async () => {
  const products = [
    {
      name: "Lay's Barbecue Potato chips 10 ounce Plastic Bag",
      price: 165, // $1.99 -> ₹165
      imageUrl: "https://i5.walmartimages.com/seo/Lay-s-Potato-Chips-Barbecue-Flavor-7-75-oz-Bag_3a3bac6f-c3c1-4deb-ac5f-ed76e17e3009.00bf1b0ce6421683a4453591073ec472.jpeg?odnHeight=640&odnWidth=640&odnBg=FFFFFF",
      rating: 4.3,
      numRatings: 320,
    },
    {
      name: "Mountain Dew, 12 oz Cans, 24 Count",
      price: 1280, // $15.38 -> ₹1280
      imageUrl: "https://i5.walmartimages.com/seo/Mountain-Dew-Citrus-Soda-Pop-12-fl-oz-24-Pack-Cans_494e5289-3e35-4383-93e9-87102b36b395_3.183a53c8dc8e9aea9f13e77eca9bc94b.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.7,
      numRatings: 1020,
    },
    {
      name: "Fresh Yellow Peach, Each",
      price: 65, // $0.78 -> ₹65
      imageUrl: "https://i5.walmartimages.com/seo/Fresh-Yellow-Peach-Each_f387846e-47eb-470f-a8e6-bcada0848532.64a94b8c68019d577dede8f236d97aa3.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.5,
      numRatings: 890,
    },
    {
      name: "Camping Lantern With Ceiling Fan",
      price: 830, // $9.99 -> ₹830
      imageUrl: "https://i5.walmartimages.com/seo/Camping-Lantern-With-Ceiling-Fan-Weather-Resistant-Tent-Light-Camping-Accessories-Gear-With-18-LED-Bulbs-and-Hi-Lo-Fan-Black-by-Wakeman-Outdoors_1392a931-342e-4909-8815-126cb20bca51_1.178cb50a07f59a46d0075c9be3e6d7ee.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.2,
      numRatings: 650,
    },
    {
      name: "Expert Grill Refillable Grill Lighter, 2-Pack",
      price: 500, // $5.99 -> ₹500
      imageUrl: "https://i5.walmartimages.com/seo/Expert-Grill-Refillable-Grill-Lighter-2-Pack_5716eab1-617b-45fc-bac4-11b5ea3ac06e.a9d26704a779800f2a65321b86ea725f.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.6,
      numRatings: 420,
    },
    {
      name: "Johnson & Johnson First Aid To Go Portable Mini Travel Kit, 12 pieces",
      price: 335, // $4.02 -> ₹335
      imageUrl: "https://i5.walmartimages.com/seo/Johnson-Johnson-First-Aid-To-Go-Portable-Mini-Travel-Kit-12-pieces_67899955-0d07-4ebe-9b8b-b03828ca348a.379e77d100850af7326e74b197885316.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.8,
      numRatings: 510,
    },
    {
      name: "Ozark Trail 7-Piece Camping Tool Set",
      price: 1650, // $19.88 -> ₹1650
      imageUrl: "https://i5.walmartimages.com/seo/Ozark-Trail-7-piece-Camping-Tool-Set-with-Hammer-Axe-Flashlight-and-Knives-Batteries-Included_7b40b324-896e-4f62-a862-5e596a2697d5.6251cfc438167631ec3d7f219622def8.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.3,
      numRatings: 320,
    },
    {
      name: "Aimerla Camping Cooking Utensil Set - 15 Pcs",
      price: 1700, // $20.48 -> ₹1700
      imageUrl: "https://i5.walmartimages.com/seo/Aimerla-Camping-Cooking-Utensil-Set-15-Pcs-Camping-Cookware-Kit-Durable-Grill-and-Camping-Accessories-for-Camping-Trip-BBQ-Hiking-RV-Travel_aab765cc-8164-4717-97a5-a4ba8194aefb.5d6f1fb290f3b63bf63ecd69c7248435.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.7,
      numRatings: 220,
    },
    {
      name: "Coleman All-Purpose Propane Gas Cylinder, 16 ounce, 2-Pack",
      price: 1320, // $15.89 -> ₹1320
      imageUrl: "https://i5.walmartimages.com/seo/Coleman-All-Purpose-Propane-Gas-Cylinder-16-ounce-2-Pack_d1fa82c6-1ed1-4f14-aea6-6ee444844785.08680bdc0276e2472156759cfffc68fb.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.4,
      numRatings: 180,
    },
    {
      name: "Portable Camping Shower Outdoor USB Rechargeable",
      price: 2000, // $24.10 -> ₹2000
      imageUrl: "https://i5.walmartimages.com/seo/Portable-Camping-Shower-Outdoor-USB-Rechargeable-Electric-Shower-Pump-for-Camping-Car-Washing-Gardening-Pet-Cleaning_41860cb3-c3a9-4f02-ad2c-3ecd83374fb1.ea212a5628108019847d2db30e5ad5ae.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.5,
      numRatings: 360,
    },
    {
      name: "KingCamp 17/25 PCS Stainless Steel Camping Cookware Set",
      price: 3000, // $36.15 -> ₹3000
      imageUrl: "https://i5.walmartimages.com/seo/KingCamp-17-25-PCS-Stainless-Steel-Camping-Cookware-Set-Nonstick-Lightweight-Compact-Backpacking-Cooking-Kit-Outdoor-Picnic-Hiking-3-People-Includes_ebbd91b5-07f1-444d-9283-8f5d043bf983.1fef184bc43a564ee7848341f241fe20.jpeg?odnHeight=2000&odnWidth=2000&odnBg=FFFFFF",
      rating: 4.8,
      numRatings: 140,
    },
  ];
  
  

  for (const product of products) {
    await prisma.product.create({
      data: product,
    });
  }

  console.log('Products have been seeded');
};

main()
  .catch(e => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
