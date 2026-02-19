import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  CreditCard,
  Shield,
  Check,
  Loader2,
  ArrowLeft,
  Lock,
  Zap,
  Server,
  Gift,
} from "lucide-react";
import { Link } from "wouter";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";

interface PlanDetails {
  id: string;
  name: string;
  price: number;
  annualPrice: number;
  features: string[];
  stripePriceIdMonthly: string;
  stripePriceIdAnnual: string;
  icon: typeof Zap;
}

const plans: Record<string, PlanDetails> = {
  pro: {
    id: "pro",
    name: "Pro",
    price: 19,
    annualPrice: 15,
    features: [
      "Cloud LLMs (GPT-4, Claude)",
      "Web console dashboard",
      "Email support (24h response)",
      "Priority updates",
      "API access",
    ],
    stripePriceIdMonthly: "price_1SqYQjJ4X1wkC4EsLDB6ZbOk",  // CX Core+ $20/mo
    stripePriceIdAnnual: "price_1SqYQjJ4X1wkC4EslIkZEJFZ",   // CX Core+ $200/year
    icon: Zap,
  },
  team: {
    id: "team",
    name: "Team",
    price: 99,
    annualPrice: 79,
    features: [
      "Everything in Pro",
      "Team workspaces",
      "Role-based access control",
      "Shared command history",
      "Priority support (4h)",
    ],
    stripePriceIdMonthly: "price_1SqYQkJ4X1wkC4Es8OMt79pZ",  // CX Pro+ $99/mo
    stripePriceIdAnnual: "price_1SqYQkJ4X1wkC4EsWYwUgceu",   // CX Pro+ $990/year
    icon: Shield,
  },
  enterprise: {
    id: "enterprise",
    name: "Enterprise",
    price: 199,
    annualPrice: 159,
    features: [
      "SSO/LDAP integration",
      "Audit logs & compliance",
      "SOC2 & HIPAA reports",
      "99.9% SLA guarantee",
      "Dedicated Slack channel",
    ],
    stripePriceIdMonthly: "price_1SqYQkJ4X1wkC4EsCFVBHYnT",  // CX Enterprise+ $299/mo
    stripePriceIdAnnual: "price_1SqYQlJ4X1wkC4EsJcPW7Of2",   // CX Enterprise+ $2990/year
    icon: Server,
  },
};

export default function CheckoutPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();

  // Parse URL params
  const params = new URLSearchParams(window.location.search);
  const planId = params.get("plan") || "pro";
  const billingCycle = params.get("billing") || "monthly";
  const referralCode = params.get("ref") || localStorage.getItem("cx_referral") || "";

  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [company, setCompany] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isAnnual, setIsAnnual] = useState(billingCycle === "annual");

  const plan = plans[planId] || plans.pro;
  const currentPrice = isAnnual ? plan.annualPrice : plan.price;
  const priceId = isAnnual ? plan.stripePriceIdAnnual : plan.stripePriceIdMonthly;

  // Store referral code in localStorage for persistence
  useEffect(() => {
    const urlRef = params.get("ref");
    if (urlRef) {
      localStorage.setItem("cx_referral", urlRef);
    }
  }, []);

  useEffect(() => {
    setIsAnnual(billingCycle === "annual");
  }, [billingCycle]);

  const handleCheckout = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email || !name) {
      toast({
        title: "Missing Information",
        description: "Please fill in your name and email address.",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);

    try {
      // Get referral code from localStorage (in case URL param was cleared)
      const ref = referralCode || localStorage.getItem("cx_referral") || "";
      
      // Create checkout session with referral code
      const response = await fetch("/api/stripe/checkout-session", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          name,
          company,
          priceId,
          planId: plan.id,
          billingCycle: isAnnual ? "annual" : "monthly",
          referralCode: ref,  // Pass referral code to backend
          successUrl: `${window.location.origin}/pricing/success?session_id={CHECKOUT_SESSION_ID}`,
          cancelUrl: `${window.location.origin}/pricing/checkout?plan=${planId}&billing=${isAnnual ? "annual" : "monthly"}${ref ? `&ref=${ref}` : ""}`,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to create checkout session");
      }

      // Clear referral code on successful checkout start
      // (it will be recorded by the webhook)
      
      // Redirect to Stripe Checkout
      if (data.url) {
        window.location.href = data.url;
      } else {
        throw new Error("No checkout URL returned");
      }
    } catch (error) {
      console.error("Checkout error:", error);
      toast({
        title: "Checkout Error",
        description: error instanceof Error ? error.message : "Failed to start checkout. Please try again.",
        variant: "destructive",
      });
      setIsLoading(false);
    }
  };

  return (
    <div id="checkout-page-container" className="min-h-screen bg-black text-white">
      <div className="max-w-6xl mx-auto px-4 py-24">
        {/* Back Link */}
        <Link
          id="checkout-back-link"
          href="/pricing"
          className="inline-flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Pricing
        </Link>

        <div className="grid lg:grid-cols-2 gap-12">
          {/* Left Column - Form */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h1 id="checkout-title" className="text-3xl font-bold mb-2">
              Complete Your Subscription
            </h1>
            <p id="checkout-subtitle" className="text-gray-400 mb-8">
              Secure checkout powered by Stripe.
            </p>

            {/* Referral Badge */}
            {referralCode && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-400/30 rounded-xl p-4 mb-6 flex items-center gap-3"
              >
                <Gift className="w-5 h-5 text-green-400" />
                <div>
                  <p className="font-semibold text-green-400">Referred by a friend</p>
                  <p className="text-sm text-gray-400">
                    Code: <span className="font-mono text-green-300">{referralCode}</span>
                  </p>
                </div>
              </motion.div>
            )}

            <form id="checkout-form" onSubmit={handleCheckout} className="space-y-6">
              <div id="checkout-field-name">
                <Label htmlFor="name" className="text-gray-300">
                  Full Name <span className="text-red-400">*</span>
                </Label>
                <Input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="John Doe"
                  required
                  className="mt-2 bg-white/5 border-white/10 text-white placeholder:text-gray-500 focus:border-purple-400"
                />
              </div>

              <div id="checkout-field-email">
                <Label htmlFor="email" className="text-gray-300">
                  Email Address <span className="text-red-400">*</span>
                </Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="john@company.com"
                  required
                  className="mt-2 bg-white/5 border-white/10 text-white placeholder:text-gray-500 focus:border-purple-400"
                />
              </div>

              <div id="checkout-field-company">
                <Label htmlFor="company" className="text-gray-300">
                  Company Name <span className="text-gray-500">(Optional)</span>
                </Label>
                <Input
                  id="company"
                  type="text"
                  value={company}
                  onChange={(e) => setCompany(e.target.value)}
                  placeholder="Acme Corp"
                  className="mt-2 bg-white/5 border-white/10 text-white placeholder:text-gray-500 focus:border-purple-400"
                />
              </div>

              {/* Billing Toggle */}
              <div id="checkout-billing-toggle" className="bg-white/5 border border-white/10 rounded-xl p-4">
                <p className="text-sm text-gray-400 mb-3">Billing Cycle</p>
                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={() => setIsAnnual(false)}
                    className={`flex-1 py-3 px-4 rounded-lg text-sm font-medium transition-all ${
                      !isAnnual
                        ? "bg-purple-500 text-white"
                        : "bg-white/5 text-gray-400 hover:bg-white/10"
                    }`}
                  >
                    Monthly
                    <span className="block text-xs mt-1 opacity-75">${plan.price}/mo</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsAnnual(true)}
                    className={`flex-1 py-3 px-4 rounded-lg text-sm font-medium transition-all ${
                      isAnnual
                        ? "bg-purple-500 text-white"
                        : "bg-white/5 text-gray-400 hover:bg-white/10"
                    }`}
                  >
                    Annual
                    <span className="block text-xs mt-1 opacity-75">
                      ${plan.annualPrice}/mo{" "}
                      <span className="text-green-400">Save 20%</span>
                    </span>
                  </button>
                </div>
              </div>

              <button
                id="checkout-submit-btn"
                type="submit"
                disabled={isLoading}
                className="w-full py-4 bg-purple-500 text-white font-semibold rounded-lg hover:bg-purple-600 hover:shadow-[0_0_20px_rgba(124,58,237,0.5)] transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Processing...
                  </>
                ) : (
                  <>
                    <CreditCard className="w-5 h-5" />
                    Subscribe Now
                  </>
                )}
              </button>

              {/* Security Note */}
              <div id="checkout-security-note" className="flex items-center justify-center gap-2 text-sm text-gray-500">
                <Lock className="w-4 h-4" />
                Secured by Stripe. Your payment info is encrypted.
              </div>
            </form>
          </motion.div>

          {/* Right Column - Order Summary */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div id="checkout-order-summary" className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-6 sticky top-24">
              <h2 id="checkout-summary-title" className="text-xl font-bold mb-6">Order Summary</h2>

              {/* Plan Card */}
              <div id="checkout-plan-card" className="bg-gradient-to-r from-purple-500/10 to-purple-500/10 border border-purple-400/30 rounded-xl p-4 mb-6">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                    <plan.icon className="w-5 h-5 text-purple-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold">{plan.name} Plan</h3>
                    <p className="text-sm text-gray-400">
                      {isAnnual ? "Billed annually" : "Billed monthly"}
                    </p>
                  </div>
                </div>
                <ul className="space-y-2">
                  {plan.features.slice(0, 3).map((feature, i) => (
                    <li key={i} className="flex items-center gap-2 text-sm text-gray-300">
                      <Check className="w-4 h-4 text-green-400" />
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Price Breakdown */}
              <div id="checkout-price-breakdown" className="space-y-3 mb-6">
                <div className="flex justify-between text-gray-400">
                  <span>{plan.name} ({isAnnual ? "Annual" : "Monthly"})</span>
                  <span>${currentPrice}/mo</span>
                </div>
                {isAnnual && (
                  <div className="flex justify-between text-green-400 text-sm">
                    <span>Annual discount (20%)</span>
                    <span>-${(plan.price - plan.annualPrice) * 12}/yr</span>
                  </div>
                )}
                <div className="border-t border-white/10 pt-3">
                  <div className="flex justify-between text-lg font-bold">
                    <span>Due today</span>
                    <span className="text-green-400">${isAnnual ? plan.annualPrice * 12 : currentPrice}{isAnnual ? "/yr" : "/mo"}</span>
                  </div>
                </div>
              </div>

              {/* Guarantee */}
              <div id="checkout-guarantee" className="bg-green-500/10 border border-green-400/30 rounded-lg p-4 mb-6">
                <div className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-green-400 mt-0.5" />
                  <div>
                    <p className="font-semibold text-green-400">30-Day Money Back</p>
                    <p className="text-sm text-gray-400">
                      Not satisfied? Get a full refund within 30 days, no questions asked.
                    </p>
                  </div>
                </div>
              </div>

              {/* Trust Signals */}
              <div id="checkout-trust-signals" className="flex items-center justify-center gap-6 text-gray-500 text-sm">
                <div className="flex items-center gap-1">
                  <Lock className="w-4 h-4" />
                  <span>SSL Encrypted</span>
                </div>
                <div className="flex items-center gap-1">
                  <Shield className="w-4 h-4" />
                  <span>SOC2 Compliant</span>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
